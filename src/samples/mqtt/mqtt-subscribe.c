/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2015 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * @brief MQTT Publish client
 *
 * Sample client that connects a broker at host:port and subscribes to
 * the provided topic. Whenever a new message is published to that topic,
 * it is printed in the console.
 */

#include <string.h>

#include <sol-log.h>
#include <sol-mainloop.h>
#include <sol-mqtt.h>

static char *topic;

static void
on_message(void *data, struct sol_mqtt *mqtt, const struct sol_mqtt_message *message)
{
    SOL_NULL_CHECK(message);

    SOL_INF("%.*s", (int)message->payload->used, (char *)message->payload->data);
}

static bool
try_reconnect(void *data)
{
    return sol_mqtt_reconnect((struct sol_mqtt *)data) != 0;
}

static void
on_connect(void *data, struct sol_mqtt *mqtt)
{
    if (sol_mqtt_get_connection_status(mqtt) != SOL_MQTT_CONNECTED) {
        SOL_WRN("Unable to connect, retrying...");
        sol_timeout_add(1000, try_reconnect, mqtt);
        return;
    }

    if (sol_mqtt_subscribe(mqtt, topic, SOL_MQTT_QOS_AT_MOST_ONCE))
        SOL_ERR("Unable to subscribe to topic %s", topic);
}

static void
on_disconnect(void *data, struct sol_mqtt *mqtt)
{
    SOL_INF("Reconnecting...");
    sol_timeout_add(1000, try_reconnect, mqtt);
}

const struct sol_mqtt_config config = {
    SOL_SET_API_VERSION(.api_version = SOL_MQTT_CONFIG_API_VERSION, )
    .clean_session = true,
    .keepalive = 60,
    .handlers = {
        .connect = on_connect,
        .disconnect = on_disconnect,
        .message = on_message,
    },
};

int
main(int argc, char *argv[])
{
    struct sol_mqtt *mqtt;
    int port;

    sol_init();

    if (argc < 4) {
        SOL_INF("Usage: %s <ip> <port> <topic>", argv[0]);
        return 0;
    }

    port = atoi(argv[2]);
    topic = argv[3];

    mqtt = sol_mqtt_connect(argv[1], port, &config, NULL);
    if (!mqtt) {
        SOL_WRN("Unable to create MQTT session");
        return -1;
    }

    sol_run();

    sol_mqtt_disconnect(mqtt);

    sol_shutdown();

    return 0;
}
