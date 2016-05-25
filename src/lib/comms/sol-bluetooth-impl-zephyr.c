/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2016 Intel Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sol-log.h>
#include <sol-network.h>
#include <sol-bluetooth.h>
#include <sol-util-internal.h>

#include "sol-bluetooth-impl-zephyr.h"

#define BLUETOOTH_INQUIRY_RESPONSE 240
#define BLUETOOTH_SHORT_NAME 0x08
#define BLUETOOTH_COMPLETE_NAME 0x09

struct sol_bt_session {
    void (*enabled)(void *data, bool powered);
    const void *user_data;
};

struct sol_bt_scan_pending {
    void (*callback)(void *user_data, const struct sol_bt_device_info *device);
    const void *user_data;
    enum sol_bt_transport transport;
#ifdef HAVE_ZEPHYR_BLUETOOTH_BREDR
    struct bt_br_discovery_result results[5];
#endif
};

/* Init vectors here  */
static struct context context = {
    .sessions = SOL_PTR_VECTOR_INIT,
    .scans = SOL_PTR_VECTOR_INIT,
    .conns = SOL_PTR_VECTOR_INIT,
    .devices = SOL_PTR_VECTOR_INIT,
};

struct context *
bluetooth_get_context(void)
{
    return &context;
}

static struct sol_bt_device_info *
find_device_by_addr(const struct sol_network_link_addr *addr)
{
    uint16_t i;
    struct sol_bt_device_info *device;

    SOL_PTR_VECTOR_FOREACH_IDX (&context.devices, device, i) {
        if (sol_network_link_addr_eq(addr, &device->addr))
            return device;
    }

    return NULL;
}

static void
link_addr_to_bt_addr(const struct sol_network_link_addr *addr, bt_addr_t *peer)
{
    memcpy(&peer->val, &addr->addr.bt_addr, 6);
}

static int
bt_connect(struct sol_bt_conn *conn, const struct sol_network_link_addr *addr)
{
    bt_addr_t peer;

    link_addr_to_bt_addr(addr, &peer);

    switch (addr->addr.bt_type) {
        case SOL_NETWORK_BT_ADDR_BASIC_RATE:
#ifdef HAVE_ZEPHYR_BLUETOOTH_BREDR
            conn->conn = bt_conn_create_br(&peer, BT_BR_CONN_PARAM_DEFAULT);
#else
            return -ENOSYS;
#endif
            break;
        case SOL_NETWORK_BT_ADDR_LE_PUBLIC:
        case SOL_NETWORK_BT_ADDR_LE_RANDOM:
#ifdef HAVE_ZEPHYR_BLUETOOTH_LE
            conn->conn = bt_conn_create_le((&(bt_addr_le_t) {
                .type = addr->addr.bt_type == SOL_NETWORK_BT_ADDR_LE_PUBLIC ?
                    BT_ADDR_LE_PUBLIC : BT_ADDR_LE_RANDOM,
                .a = peer,
                }), BT_LE_CONN_PARAM_DEFAULT);
#else
            return -ENOSYS;
#endif
            break;
        default:
        break;
    }

    return conn->conn ? 0 : -EINVAL;
}

static void
bt_disconnect(struct sol_bt_conn *conn)
{
    if (conn->on_disconnect)
        conn->on_disconnect((void *)conn->user_data, conn);

    bt_conn_disconnect(conn->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    free(conn);
}

SOL_API struct sol_bt_conn *
sol_bt_conn_ref(struct sol_bt_conn *conn)
{
    SOL_NULL_CHECK(conn, NULL);

    conn->ref++;

    return conn;
}

SOL_API void
sol_bt_conn_unref(struct sol_bt_conn *conn)
{
    if (!conn)
        return;

    conn->ref--;

    if (conn->ref > 0)
        return;

    sol_ptr_vector_remove(&context.conns, conn);
    bt_disconnect(conn);
}

SOL_API struct sol_bt_conn *
sol_bt_connect(const struct sol_network_link_addr *addr,
    bool (*on_connect)(void *user_data, struct sol_bt_conn *conn),
    void (*on_disconnect)(void *user_data, struct sol_bt_conn *conn),
    void (*on_error)(void *user_data, int error),
    const void *user_data)
{
    struct sol_bt_device_info *d;
    struct sol_bt_conn *conn;
    int r;

    SOL_NULL_CHECK(addr, NULL);
    SOL_NULL_CHECK(on_connect, NULL);
    SOL_NULL_CHECK(on_disconnect, NULL);
    SOL_NULL_CHECK(on_error, NULL);

    d = find_device_by_addr(addr);
    SOL_NULL_CHECK(d, NULL);

    conn = calloc(1, sizeof(*conn));
    SOL_NULL_CHECK(conn, NULL);

    conn->d = d;
    conn->on_connect = on_connect;
    conn->on_disconnect = on_disconnect;
    conn->on_error = on_error;
    conn->user_data = user_data;
    conn->ref = 1;

    r = sol_ptr_vector_append(&context.conns, conn);
    SOL_INT_CHECK_GOTO(r, < 0, error_append);

    r = bt_connect(conn, addr);
    SOL_INT_CHECK_GOTO(r, < 0, error_connect);

    return conn;

error_connect:
    sol_ptr_vector_remove(&context.conns, conn);

error_append:
    free(conn);
    return NULL;
}

SOL_API int
sol_bt_disconnect(struct sol_bt_conn *conn)
{
    struct sol_bt_device_info *d;
    int r;

    SOL_NULL_CHECK(conn, -EINVAL);

    r = sol_ptr_vector_remove(&context.conns, conn);
    SOL_INT_CHECK(r, < 0, -ENOENT);

    d = conn->d;
    conn->on_disconnect = NULL;
    bt_disconnect(conn);

    return 0;
}

static void
bluetooth_connected(struct bt_conn *conn, uint8_t err)
{
    struct sol_bt_conn *c;
    uint16_t idx;

    SOL_PTR_VECTOR_FOREACH_IDX (&context.conns, c, idx) {
        if (c->conn == conn) {
            if (err)
                c->on_error((void *)c->user_data, err);
            else
                c->on_connect((void *)c->user_data, c);

            return;
        }
    }

    /*
     *TODO: Create a new device info and sol_bt_connection to notify the user
     *      For now we disconnect.
     */
    bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

static void
bluetooth_disconnected(struct bt_conn *conn, uint8_t err)
{
    struct sol_bt_conn *c;
    uint16_t idx;

    SOL_PTR_VECTOR_FOREACH_IDX (&context.conns, c, idx) {
        if (c->conn == conn) {
            if (err)
                c->on_error((void *)c->user_data, err);
            else
                c->on_disconnect((void *)c->user_data, c);

            return;
        }
    }
}

static struct bt_conn_cb connection_callbacks = {
    .connected = bluetooth_connected,
    .disconnected = bluetooth_disconnected,
    /*
     *TODO
     */
    .le_param_updated = NULL,
};

static void
bt_ready_cb(int err)
{
    uint16_t idx;
    struct sol_bt_session *session;

    if (err < 0) {
        SOL_WRN("Failed to enable bluetooth - %s", sol_util_strerrora(err));
    } else {
        context.adapter_powered = true;
        bt_conn_cb_register(&connection_callbacks);

        nano_sem_init(&context.sem);
    }

    SOL_PTR_VECTOR_FOREACH_IDX (&context.sessions, session, idx) {
        session->enabled((void *)session->user_data, err == 0 ? true : false);
    }
}

SOL_API struct sol_bt_session *
sol_bt_enable(void (*enabled)(void *data, bool powered), const void *user_data)
{
    int r;
    struct sol_bt_session *session;

    session = calloc(1, sizeof(*session));
    SOL_NULL_CHECK(session, NULL);

    session->enabled = enabled;
    session->user_data = user_data;

    r = sol_ptr_vector_append(&context.sessions, session);
    SOL_INT_CHECK_GOTO(r, < 0, error_append);

    if (sol_ptr_vector_get_len(&context.sessions) == 1) {
        r = bt_enable(bt_ready_cb);
        SOL_INT_CHECK_GOTO(r, < 0, error_set_powered);

        return session;
    }

    session->enabled((void *)user_data, context.adapter_powered);

    return session;

error_set_powered:
    sol_ptr_vector_del_last(&context.sessions);
error_append:
    free(session);
    return NULL;
}

SOL_API int
sol_bt_disable(struct sol_bt_session *session)
{
    struct sol_bt_device_info *device;
    uint16_t idx;
    int r;

    SOL_NULL_CHECK(session, -EINVAL);

    r = sol_ptr_vector_remove(&context.sessions, session);
    SOL_INT_CHECK(r, < 0, -ENOENT);

    SOL_PTR_VECTOR_FOREACH_IDX (&context.devices, device, idx) {
        free(device->name);
        sol_vector_clear(&device->uuids);
        free(device);
    }
    sol_ptr_vector_clear(&context.devices);

    free(session);

    return 0;
}

#ifdef HAVE_ZEPHYR_BLUETOOTH_LE
static int
parse_uuid_advertisement(struct sol_bt_device_info *device,
    uint8_t *data, uint8_t len)
{
    uint8_t i;

    if (len % sizeof(uint16_t) != 0)
        return -EINVAL;

    for (i = 0; i < len; i += sizeof(uint16_t)) {
        uint16_t *uuid;

        uuid = sol_vector_append(&device->uuids);
        if (!uuid)
            return -ENOMEM;

        memcpy(uuid, &data[i], sizeof(uint16_t));
    }

    return 0;
}

static int
parse_scan_advertisement(struct sol_bt_device_info *device,
    uint8_t *data, uint8_t len)
{
    while (len > 1) {
        int r;
        uint8_t adv_len = data[0];

        if (adv_len == 0)
            return 0;

        if ((adv_len + 1) > len || (len < 2))
            return -EINVAL;

        switch (data[1]) {
            case BT_DATA_NAME_COMPLETE:
                device->name = strndup((char *)(data + 2), adv_len - 1); 
                if (!device->name)
                    return -ENOMEM;
                break;
            case BT_DATA_UUID16_SOME:
            case BT_DATA_UUID16_ALL:
                r = parse_uuid_advertisement(device, &data[2], adv_len - 1);
                if (r < 0)
                    return r;
                break;
            default:
                break;
        }

        len -= adv_len + 1;
        data += adv_len + 1;
    }

    return 0;
}

static void
scan_ble_cb(const bt_addr_le_t *addr, int8_t rssi,
    uint8_t adv_type, const uint8_t *adv_data,
    uint8_t len)
{
    int r;
    uint16_t idx;
    bool found = false;
    struct sol_bt_scan_pending *scan;
    struct sol_bt_device_info *device;

    /*
     * Ignore not connectable events/devices
     */
    if (!(adv_type == BT_LE_ADV_IND || adv_type == BT_LE_ADV_DIRECT_IND))
        return;

    SOL_PTR_VECTOR_FOREACH_IDX (&context.devices, device, idx) {
        if ((addr->type == device->addr.addr.bt_type) &&
            memcmp(&device->addr.addr.bt_addr, &addr->a, 6)) {
            found = true;
            break;
        }
    }

    if (!found) {
        device = calloc(1, sizeof(*device));
        SOL_NULL_CHECK(device);

        r = sol_ptr_vector_append(&context.devices, device);
        SOL_INT_CHECK_GOTO(r, < 0, err);

        sol_vector_init(&device->uuids, sizeof(uint16_t));
        device->addr.family = SOL_NETWORK_FAMILY_BLUETOOTH;
        device->addr.addr.bt_type = (addr->type == BT_ADDR_LE_PUBLIC) ?
            SOL_NETWORK_BT_ADDR_LE_PUBLIC : SOL_NETWORK_BT_ADDR_LE_RANDOM;
        memcpy(&device->addr.addr.bt_addr, &addr->a, 6);
    }

    device->rssi = rssi;
    device->in_range = true;

    r = parse_scan_advertisement(device, (uint8_t *)adv_data, len);
    SOL_INT_CHECK_GOTO(r, < 0, err_parse);

    SOL_PTR_VECTOR_FOREACH_IDX (&context.scans, scan, idx) {
        if (!scan->callback)
            continue;

        scan->callback((void *)scan->user_data, device);
    }

    return;

err_parse:
    sol_ptr_vector_del_element(&context.devices, device);
    free(device->name);
    sol_vector_clear(&device->uuids);
err:
    free(device);
}
#endif

static int
start_scan_ble(struct sol_bt_scan_pending *scan)
{
#ifdef HAVE_ZEPHYR_BLUETOOTH_LE
    return bt_le_scan_start(BT_LE_SCAN_ACTIVE, scan_ble_cb);
#else
    return -ENOSYS;
#endif
}

#ifdef HAVE_ZEPHYR_BLUETOOTH_BREDR
static int
parse_discovery_result(struct sol_bt_device_info *device,
    const struct bt_br_discovery_result *result)
{
    int len = BLUETOOTH_INQUIRY_RESPONSE;
    uint8_t *eir = (uint8_t *)result->eir;

    device->addr.family = SOL_NETWORK_FAMILY_BLUETOOTH;
    device->addr.addr.bt_type = SOL_NETWORK_BT_ADDR_BASIC_RATE;
    memcpy(&device->addr.addr.bt_addr, &result->addr, 6);

    while (len) {
        if (len < 2)
            break;

        if (!eir[0])
            break;

        if (eir[0] > len - 1)
            break;

        switch (eir[1]) {
        case BLUETOOTH_SHORT_NAME:
        case BLUETOOTH_COMPLETE_NAME:
            device->name = strndup(&eir[2], eir[0] - 1);
            SOL_NULL_CHECK(device->name, -ENOMEM);

            break;
        default:
            break;
        }

        len -= eir[0] + 1;
        eir += eir[0] + 1;
    }

    device->rssi = result->rssi;
    device->in_range = true;

    return 0;
}

static void
scan_bredr_cb(struct bt_br_discovery_result *results,
    size_t count)
{
    int i;
    struct sol_bt_scan_pending *scan;
    struct sol_bt_device_info device;

    for (i = 0; i < count; i++) {
        int r;
        uint16_t idx;

        device.name = NULL;
        r = parse_discovery_result(&device, &results[i]);
        if (r < 0) {
            SOL_WRN("Could not get device information from %p", &results[i]);
            continue;
        }

        SOL_PTR_VECTOR_FOREACH_IDX (&context.scans, scan, idx) {

            if (!scan->callback)
                continue;

            scan->callback((void *)scan->user_data, &device);
        }

        free(device.name);
    }
}
#endif

static int
start_scan_bredr(struct sol_bt_scan_pending *scan)
{
#ifdef HAVE_ZEPHYR_BLUETOOTH_BREDR
    return bt_br_discovery_start((&(struct bt_br_discovery_param) {
        .limited_discovery = true,
        }), scan->results, sol_util_array_size(scan->results), scan_bredr_cb);
#else
    return -ENOSYS;
#endif
}

SOL_API struct sol_bt_scan_pending *
sol_bt_start_scan(enum sol_bt_transport transport,
    void (*cb)(void *user_data, const struct sol_bt_device_info *device),
    const void *user_data)
{
    int r;
    struct sol_bt_scan_pending *scan;

    SOL_NULL_CHECK(cb, NULL);
    SOL_EXP_CHECK(context.adapter_powered == false, NULL);

    scan = calloc(1, sizeof(*scan));
    SOL_NULL_CHECK(scan, NULL);

    r = sol_ptr_vector_append(&context.scans, scan);
    SOL_INT_CHECK_GOTO(r, < 0, error_append);

    scan->transport = transport;
    scan->callback = cb;
    scan->user_data = user_data;

    if (sol_ptr_vector_get_len(&context.scans) > 1)
        return scan;

    if (scan->transport & SOL_BT_TRANSPORT_LE)
        r = start_scan_ble(scan);
    SOL_INT_CHECK_GOTO(r, < 0, error_scan);

    if (scan->transport & SOL_BT_TRANSPORT_BREDR)
        start_scan_bredr(scan);
    SOL_INT_CHECK_GOTO(r, < 0, error_scan);

    return scan;

error_scan:
    sol_ptr_vector_del_last(&context.scans);
error_append:
    free(scan);
    return NULL;
}

SOL_API int
sol_bt_stop_scan(struct sol_bt_scan_pending *scan)
{
    int r;

    SOL_NULL_CHECK(scan, -EINVAL);

    r = sol_ptr_vector_remove(&context.scans, scan);
    SOL_INT_CHECK(r, < 0, -ENOENT);

    free(scan);

    if (sol_ptr_vector_get_len(&context.scans) > 0)
        return 0;

    if (scan->transport & SOL_BT_TRANSPORT_LE) {
#ifdef HAVE_ZEPHYR_BLUETOOTH_LE
        bt_le_scan_stop();
#endif
    }

    if (scan->transport & SOL_BT_TRANSPORT_BREDR) {
#ifdef HAVE_ZEPHYR_BLUETOOTH_BREDR
        bt_br_discovery_stop();
#endif
    }

    return 0;
}

SOL_API const struct sol_network_link_addr *
sol_bt_conn_get_addr(const struct sol_bt_conn *conn)
{
    SOL_NULL_CHECK(conn, NULL);

    return &conn->d->addr;
}
