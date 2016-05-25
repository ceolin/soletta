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

#include <bluetooth/gatt.h>

#include <sol-log.h>
#include <sol-bluetooth.h>
#include <sol-network.h>
#include <sol-util.h>

#include <sol-gatt.h>

#include "sol-mainloop-zephyr.h"
#include "sol-bluetooth-impl-zephyr.h"

struct application {
    uint32_t id;
    struct sol_gatt_attr *attrs;
    struct bt_gatt_attr *bt_attrs;
};

struct sol_ptr_vector applications = SOL_PTR_VECTOR_INIT;
struct sol_ptr_vector pending_ops = SOL_PTR_VECTOR_INIT;

static uint16_t
sol_gatt_desc_flags_to_bt_gatt_attr_perm(uint16_t flags)
{
    uint16_t perms = 0x00;

    perms |= (flags & SOL_GATT_DESC_FLAGS_READ) ? BT_GATT_PERM_READ : 0;
    perms |= (flags & SOL_GATT_DESC_FLAGS_WRITE) ? BT_GATT_PERM_WRITE : 0;
    perms |= (flags & SOL_GATT_DESC_FLAGS_ENCRYPT_READ) ? BT_GATT_PERM_READ_ENCRYPT : 0;
    perms |= (flags & SOL_GATT_DESC_FLAGS_ENCRYPT_WRITE) ? BT_GATT_PERM_WRITE_ENCRYPT : 0;
    perms |= (flags & SOL_GATT_DESC_FLAGS_ENCRYPT_AUTHENTICATED_READ) ? BT_GATT_PERM_READ_AUTHEN : 0;
    perms |= (flags & SOL_GATT_DESC_FLAGS_ENCRYPT_AUTHENTICATED_WRITE) ? BT_GATT_PERM_WRITE_AUTHEN : 0;

    return perms;
}

static uint16_t
sol_gatt_chr_flags_to_bt_gatt_chrc(uint16_t flags)
{
    uint16_t chrcs = 0x00;

    chrcs |= (flags & SOL_GATT_CHR_FLAGS_BROADCAST) ? BT_GATT_CHRC_BROADCAST : 0;
    chrcs |= (flags & SOL_GATT_CHR_FLAGS_READ) ? BT_GATT_CHRC_READ : 0;
    chrcs |= (flags & SOL_GATT_CHR_FLAGS_WRITE) ? BT_GATT_CHRC_WRITE : 0;
    chrcs |= (flags & SOL_GATT_CHR_FLAGS_WRITE_WITHOUT_RESPONSE) ? BT_GATT_CHRC_WRITE_WITHOUT_RESP : 0;
    chrcs |= (flags & SOL_GATT_CHR_FLAGS_NOTIFY) ? BT_GATT_CHRC_NOTIFY : 0;
    chrcs |= (flags & SOL_GATT_CHR_FLAGS_INDICATE) ? BT_GATT_CHRC_INDICATE : 0;

    return chrcs;
}

static uint16_t
sol_gatt_chr_flags_to_bt_gatt_perm(uint16_t flags)
{
    uint16_t perms = 0x00;

    perms |= (flags & SOL_GATT_CHR_FLAGS_READ) ? BT_GATT_PERM_READ : 0;
    perms |= (flags & SOL_GATT_CHR_FLAGS_WRITE) ? BT_GATT_PERM_WRITE : 0;
    /*
     *TODO: Check whether others characteristics should be mapped.
     */

    return perms;
}

static void
destroy_pending(struct sol_gatt_pending *op)
{
    sol_buffer_fini(&op->buf);
    free(op);
}

static void
attr_method(void *data)
{
    struct context *ctx = bluetooth_get_context();
    struct sol_gatt_pending *pending = data;

    switch (pending->type) {
        case PENDING_WRITE:
            pending->error = pending->attr->write(pending,
                &pending->buf, pending->offset);
            SOL_INT_CHECK_GOTO(pending->error, < 0, error);
            break;
        case PENDING_READ:
            pending->error = pending->attr->read(pending,
                pending->offset);
            SOL_INT_CHECK_GOTO(pending->error, < 0, error);
            break;
        default:
            pending->error = -EINVAL;
            goto error;
    }

    return;

error:
    nano_sem_give(&ctx->sem);
}

static ssize_t
read_attribute(struct bt_conn *conn,  const struct bt_gatt_attr *attr,
     void *buf, uint16_t len, uint16_t offset)
{
    ssize_t r;
    struct context *ctx = bluetooth_get_context();
    struct sol_gatt_pending *pending;
    struct mainloop_event me = {
        .cb = attr_method,
    };

    pending = calloc(1, sizeof(*pending));
    SOL_NULL_CHECK(pending, -ENOMEM);

    pending->attr = attr->user_data;
    pending->type = PENDING_READ;
    pending->offset = offset;
    sol_buffer_init_flags(&pending->buf, buf, len, SOL_BUFFER_FLAGS_MEMORY_NOT_OWNED);

    r = sol_ptr_vector_append(&pending_ops, pending);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    me.data = pending;
    sol_mainloop_event_post(&me);

    nano_sem_take(&ctx->sem, TICKS_UNLIMITED);

    if (pending->error) {
        r = pending->error;
        goto error;
    }

    r = pending->buf.used;
    destroy_pending(pending);

    return r;

error:
    destroy_pending(pending);
    return r;
}

static ssize_t
write_attribute(struct bt_conn *conn,  const struct bt_gatt_attr *attr,
     const void *buf, uint16_t len, uint16_t offset)
{
    ssize_t r;
    struct context *ctx = bluetooth_get_context();
    struct sol_gatt_pending *pending;
    struct mainloop_event me = {
        .cb = attr_method,
    };

    pending = calloc(1, sizeof(*pending));
    SOL_NULL_CHECK(pending, -ENOMEM);

    pending->attr = attr->user_data;
    pending->type = PENDING_WRITE;
    pending->offset = offset;
    sol_buffer_init_flags(&pending->buf, (void *)buf, len, SOL_BUFFER_FLAGS_MEMORY_NOT_OWNED);

    r = sol_ptr_vector_append(&pending_ops, pending);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    me.data = pending;
    sol_mainloop_event_post(&me);

    nano_sem_take(&ctx->sem, TICKS_UNLIMITED);

    if (pending->error) {
        r = pending->error;
        goto error;
    }

    destroy_pending(pending);
    return offset;

error:
    destroy_pending(pending);
    return r;
}

static struct bt_uuid *
sol_bt_uuid_to_bt_uuid(const struct sol_bt_uuid *uuid)
{
    struct bt_uuid *val = NULL;

    switch (uuid->type) {
        case SOL_BT_UUID_TYPE_16:
            val = calloc(1, sizeof(struct bt_uuid_16));
            if (!val)
                return NULL;
            ((struct bt_uuid_16 *)val)->uuid.type = BT_UUID_TYPE_16;
            ((struct bt_uuid_16 *)val)->val = uuid->val16;
            break;
        case SOL_BT_UUID_TYPE_128:
            val = calloc(1, sizeof(struct bt_uuid_128));
            if (!val)
                return NULL;
            ((struct bt_uuid_128 *)val)->uuid.type = BT_UUID_TYPE_128;
            memcpy(((struct bt_uuid_128 *)val)->val, uuid->val128, sizeof(uuid->val128));
            break;
        default:
            SOL_WRN("Invalid type: %d", uuid->type);
            break;
    }

    return val;
}

static struct bt_uuid *service_uuid = BT_UUID_GATT_PRIMARY;
static struct bt_uuid *chrc_uuid = BT_UUID_GATT_CHRC;

static int
sol_gatt_attr_to_bt_gatt_attr(const struct sol_gatt_attr *attr, struct bt_gatt_attr *bt_attr)
{
    switch (attr->type) {
        case SOL_GATT_ATTR_TYPE_SERVICE:
            bt_attr->uuid = service_uuid;
            bt_attr->perm = BT_GATT_PERM_READ;
            bt_attr->read = bt_gatt_attr_read_service;
            bt_attr->user_data = sol_bt_uuid_to_bt_uuid(&attr->uuid);
            if (!bt_attr->user_data)
                return -EINVAL;
            break;

        case SOL_GATT_ATTR_TYPE_CHARACTERISTIC:
            bt_attr->uuid = chrc_uuid;
            bt_attr->read = bt_gatt_attr_read_chrc;
            bt_attr->perm = BT_GATT_PERM_READ;
            bt_attr->user_data = calloc(1, sizeof(struct bt_gatt_chrc));
            if (!bt_attr->user_data)
                return -ENOMEM;
            ((struct bt_gatt_chrc *)bt_attr->user_data)->properties =
                sol_gatt_chr_flags_to_bt_gatt_chrc(attr->flags);
            ((struct bt_gatt_chrc *)bt_attr->user_data)->uuid = sol_bt_uuid_to_bt_uuid(&attr->uuid);
            if (!((struct bt_gatt_chrc *)bt_attr->user_data)->uuid)
                goto error_chrc;
            break;

        case SOL_GATT_ATTR_TYPE_DESCRIPTOR:
            break;

        default:
            return -EINVAL;
    }

    return 0;

error_chrc:
    free(bt_attr->user_data);
    return -EINVAL;
}

static int
sol_gatt_attr_chr_to_bt_gatt_attr_chrc(const struct sol_gatt_attr *attr,
    struct bt_gatt_attr *bt_attr)
{
    bt_attr->uuid = sol_bt_uuid_to_bt_uuid(&attr->uuid);
    if (!bt_attr->uuid)
        return -EINVAL;

    bt_attr->read = (attr->read) ? read_attribute : NULL;
    bt_attr->write = (attr->write) ? write_attribute : NULL;
    bt_attr->perm = sol_gatt_chr_flags_to_bt_gatt_perm(attr->flags);
    bt_attr->user_data = (void *)attr;

    return 0;
}

SOL_API const struct sol_gatt_attr *
sol_gatt_pending_get_attr(const struct sol_gatt_pending *op)
{
    SOL_NULL_CHECK(op, NULL);

    return op->attr;
}

static struct application *
find_application(struct sol_gatt_attr *attrs)
{
    struct application *a;
    uint16_t i;

    SOL_PTR_VECTOR_FOREACH_IDX (&applications, a, i) {
        if (a->attrs == attrs)
            return a;
    }

    return NULL;
}

SOL_API int
sol_gatt_pending_reply(struct sol_gatt_pending *pending,
    int error, struct sol_buffer *buf)
{
    struct context *ctx = bluetooth_get_context();
    struct application *app;
    struct sol_gatt_attr *attr;

    SOL_NULL_CHECK(pending, -EINVAL);

    attr = pending->attr;

    app = find_application(attr);
    SOL_NULL_CHECK(app, -EINVAL);

    if (error) {
        pending->error = error;
        goto done;
    }

    switch (pending->type) {
    case PENDING_READ:
        pending->error = sol_buffer_insert_buffer(&pending->buf,
            pending->offset, buf);
        SOL_INT_CHECK_GOTO(pending->error, < 0, done);
        break;
    case PENDING_WRITE:
        break;
    case PENDING_INDICATE:
    case PENDING_NOTIFY:
        error = bt_gatt_notify(NULL, app->bt_attrs,
		   buf->data, (uint16_t) buf->used);
        SOL_INT_CHECK(error, < 0, error);
        return 0;
        break;
    case PENDING_REMOTE_READ:
        break;
    case PENDING_REMOTE_WRITE:
        break;
    default:
        SOL_WRN("Invalid type: %d", pending->type);
        pending->error = -EINVAL;
        goto done;
        break;
    }

done:
    nano_sem_give(&ctx->sem);
    return pending->error;
}

static unsigned int
sol_gatt_attrs_count(struct sol_gatt_attr *attrs)
{
    unsigned int count = 0;
    struct sol_gatt_attr *attr;

    for (attr = attrs; attr && attr->type != SOL_GATT_ATTR_TYPE_INVALID;
        attr++) {
        /*
         *TODO: Check if it requires CCC
         */
        if (attr->type == SOL_GATT_ATTR_TYPE_CHARACTERISTIC)
            count++;

        count++;
    }

    return count;
}

static void
bt_attrs_free(struct bt_gatt_attr *bt_attrs, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        struct bt_gatt_attr *attr = bt_attrs + i;
        struct bt_uuid *uuid = (struct bt_uuid *)attr->uuid;
        if (uuid == service_uuid || uuid == chrc_uuid)
            free(attr->user_data);
        else
            free(uuid);
    }
    free(bt_attrs);
}

SOL_API int
sol_gatt_register_attributes(struct sol_gatt_attr *attrs)
{
    int r;
    bool service = false;
    struct context *ctx = bluetooth_get_context();
    struct sol_gatt_attr *attr;
    struct application *app;
    enum sol_gatt_attr_type previous = SOL_GATT_ATTR_TYPE_INVALID;
    static unsigned int app_id;
    size_t i = 0, count = sol_gatt_attrs_count(attrs);

    SOL_NULL_CHECK(attrs, -EINVAL);

    app = find_application(attrs);
    if (app)
        return -EALREADY;

    SOL_EXP_CHECK(ctx->adapter_powered == false, -EINVAL);

    app = calloc(1, sizeof(*app));
    SOL_NULL_CHECK(app, -ENOMEM);

    r = sol_ptr_vector_append(&applications, app);
    SOL_INT_CHECK_GOTO(r, < 0, error_append);

    app->attrs = attrs;
    app->id = ++app_id;

    app->bt_attrs = calloc(count, sizeof(*app->bt_attrs));
    SOL_NULL_CHECK_GOTO(app->bt_attrs, error_calloc);

    for (attr = attrs; attr && attr->type != SOL_GATT_ATTR_TYPE_INVALID;
        attr++) {

        switch (attr->type) {
        case SOL_GATT_ATTR_TYPE_SERVICE:
            service = true;
            r = sol_gatt_attr_to_bt_gatt_attr(attr, app->bt_attrs + i);
            SOL_INT_CHECK_GOTO(r, < 0, error_vtable);
            break;


        case SOL_GATT_ATTR_TYPE_CHARACTERISTIC:
            if (previous == SOL_GATT_ATTR_TYPE_INVALID || !service) {
                SOL_WRN("invalid type sequence %d -> %d", previous, attr->type);
                r = -EINVAL;
                goto error_vtable;
            }
            r = sol_gatt_attr_to_bt_gatt_attr(attr, app->bt_attrs + i);
            SOL_INT_CHECK_GOTO(r, < 0, error_vtable);
            i++;
            r = sol_gatt_attr_chr_to_bt_gatt_attr_chrc(attr, app->bt_attrs + i);
            SOL_INT_CHECK_GOTO(r, < 0, error_vtable);
            break;

        case SOL_GATT_ATTR_TYPE_DESCRIPTOR:
            if (previous == SOL_GATT_ATTR_TYPE_INVALID
                || previous == SOL_GATT_ATTR_TYPE_SERVICE || !service) {
                SOL_WRN("invalid type sequence %d -> %d", previous, attr->type);
                r = -EINVAL;
                goto error_vtable;
            }
            break;

        default:
            SOL_WRN("Invalid attribute type %d", attr->type);
            r = -EINVAL;
            goto error_vtable;
        }

        previous = attr->type;
        i++;
    }

    r = bt_gatt_register(app->bt_attrs, count);
    SOL_INT_CHECK_GOTO(r, < 0, error_vtable);

    return 0;

error_vtable:
    bt_attrs_free(app->bt_attrs, i);

error_calloc:
    sol_ptr_vector_del_last(&applications);

error_append:
    free(app);

    return r;
}

SOL_API int
sol_gatt_unregister_attributes(struct sol_gatt_attr *attrs)
{
    struct application *app;

    app = find_application(attrs);
    if (!app)
        return -ENOENT;

    /*
     *TODO: Unregister the attributes
     */
    bt_attrs_free(app->bt_attrs,sol_util_array_size(attrs));
    sol_ptr_vector_remove(&applications, app);

    free(app);

    return 0;
}

SOL_API int
sol_gatt_read_attr(struct sol_bt_conn *conn, struct sol_gatt_attr *attr,
    void (*cb)(void *user_data, bool success,
    const struct sol_gatt_attr *attr,
    const struct sol_buffer *buf),
    const void *user_data)
{
    return 0;
}

SOL_API int
sol_gatt_write_attr(struct sol_bt_conn *conn, struct sol_gatt_attr *attr,
    struct sol_buffer *buf,
    void (*cb)(void *user_data, bool success,
    const struct sol_gatt_attr *attr),
    const void *user_data)
{
    return 0;
}

SOL_API int
sol_gatt_discover(struct sol_bt_conn *conn, enum sol_gatt_attr_type type,
    const struct sol_gatt_attr *parent,
    const struct sol_bt_uuid *uuid,
    bool (*cb)(void *user_data, struct sol_bt_conn *conn,
    const struct sol_gatt_attr *attr),
    const void *user_data)
{
    return 0;
}

SOL_API int
sol_gatt_subscribe(struct sol_bt_conn *conn, const struct sol_gatt_attr *attr,
    bool (*cb)(void *user_data, const struct sol_gatt_attr *attr,
    const struct sol_buffer *buffer),
    const void *user_data)
{
    return 0;
}

SOL_API int
sol_gatt_unsubscribe(bool (*cb)(void *user_data, const struct sol_gatt_attr *attr,
    const struct sol_buffer *buffer),
    const void *user_data)
{
    return 0;
}

static int
prepare_update(enum pending_type type, const struct sol_gatt_attr *attr)
{
    struct sol_gatt_pending *pending;
    int r;

    SOL_NULL_CHECK(attr, -EINVAL);
    SOL_NULL_CHECK(attr->read, -EINVAL);

    pending = calloc(1, sizeof(*pending));
    SOL_NULL_CHECK(pending, -ENOMEM);

    pending->attr = attr;
    pending->type = type;

    r = sol_ptr_vector_append(&pending_ops, pending);
    SOL_INT_CHECK_GOTO(r, < 0, error_append);

    r = attr->read(pending, 0);
    SOL_INT_CHECK_GOTO(r, < 0, error_read);

    return 0;

error_read:
    sol_ptr_vector_del_last(&pending_ops);

error_append:
    free(pending);
    return r;
}

SOL_API int
sol_gatt_indicate(struct sol_bt_conn *conn, const struct sol_gatt_attr *attr)
{
    return prepare_update(PENDING_INDICATE, attr);
}

SOL_API int
sol_gatt_notify(struct sol_bt_conn *conn, const struct sol_gatt_attr *attr)
{
    return prepare_update(PENDING_NOTIFY, attr);
}

static void
destroy_application(struct application *app)
{
    bt_attrs_free(app->bt_attrs, sol_util_array_size(app->bt_attrs));
    sol_ptr_vector_remove(&applications, app);
    free(app);
}

void
clear_applications(void)
{
    struct sol_gatt_pending *pending;
    struct application *app;
    uint16_t idx;

    SOL_PTR_VECTOR_FOREACH_IDX (&applications, app, idx) {
        destroy_application(app);
    }
    sol_ptr_vector_clear(&applications);

    SOL_PTR_VECTOR_FOREACH_IDX (&pending_ops, pending, idx) {
        destroy_pending(pending);
    }
    sol_ptr_vector_clear(&pending_ops);
}
