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

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>

struct context {
    char *adapter_path;
    struct sol_ptr_vector devices;
    struct sol_ptr_vector sessions;
    struct sol_ptr_vector scans;
    struct sol_ptr_vector conns;
    bool adapter_powered;
};

struct sol_bt_conn {
    struct sol_bt_device_info *d;
    struct bt_conn *conn;
    bool (*on_connect)(void *user_data, struct sol_bt_conn *conn);
    void (*on_disconnect)(void *user_data, struct sol_bt_conn *conn);
    void (*on_error)(void *user_data, int error);
    const void *user_data;
    int ref;
};

struct context *bluetooth_get_context(void);
