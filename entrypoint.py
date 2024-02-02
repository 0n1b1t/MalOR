import pika
import json
import time
import logging
import os
from config.modules import __decoders__
from config.utils import SendEmail
import traceback
from base64 import b64decode, b64encode

rabbitmq_config = {
    "bot_name": "malor",
    "server": "amqp://user:password@rabbitmq_server:5672/",
    "server_hostname": "",
    "username": "",
    "password": "",
    "exchange": "malor.topic",
    "exchange_routing_key": "malor.analysis.out.decoder",
    "input_queue": "malor.analysis.in",
    "output_queue": "malor.analysis.out"
}

def process_message_data(msg):
    pass

def send_message_to_queue(channel_obj, exchange_name, routing_key, msg):
    channel_obj.basic_publish(exchange_name, routing_key, properties=channel_properties, body=msg)
    return


def on_open(connection):
    connection.channel(on_open_callback=on_channel_open)


def on_channel_open(channel):
    # TODO: This function can be used to setup mutiple monioring queues. This is to support one RabbitMQ queue per decoder
    queue_name = rabbitmq_config['input_queue']
    logger.info(f"Moniting {queue_name} Queue...")
    channel.basic_consume(queue=queue_name, on_message_callback=process_messages, auto_ack=True, consumer_tag=queue_name)


def process_messages(channel, method, header_frame, body):
    try:
        msg_content = json.loads(body)
        if "filename" in msg_content and "filepath" in msg_content:
            logger.info("Processing new message from: {}\n".format(msg_content))
            if msg_content['filename']:
                filepath = msg_content['filepath']
                if os.path.exists(filepath) and os.path.isfile(filepath):
                    module_to_load = msg_content['rule'].lower()
                    for d in __decoders__:
                        if d in module_to_load:
                            module_to_load = d
                            time_epoch = int(time.time())
                            sample_md5 = msg_content.get("md5")
                            sample_sha1 = msg_content.get("sha1")
                            sample_filename = msg_content.get("filename")
                            sample_sha256 = msg_content.get("sha256")
                            sample_size = msg_content.get("file_size")
                            sample_file_type = msg_content.get("file_type")
                            sample_trrigered_rule = msg_content.get("rule")
                            sample_classification_result = msg_content.get("classification_result")
                            sample_risk_score = msg_content.get("riskscore")
                            sample_classification = msg_content.get("classification")
                            sample_log = {
                                "application": "malor",
                                "filepath": filepath,
                                "malor_analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_epoch)),
                                "malor_analysis_timestamp_epoch": time_epoch,
                                "result": "success",
                                "md5": sample_md5,
                                "sha1": sample_sha1,
                                "sha256": sample_sha256,
                                "filename": sample_filename,
                                "malor_decoder_name": module_to_load,
                                "classification_result": sample_classification_result,
                                "riskscore": sample_risk_score,
                                "file_type": sample_file_type,
                                "file_size": sample_size,
                                "classification": sample_classification,
                                "triggered_rule": sample_trrigered_rule
                            }
                            logger.info(f"{module_to_load}: Analyzing {filepath}")
                            decoder = __decoders__[module_to_load]['obj']()
                            result = decoder.config(filepath)
                            if result:
                                logger.info(f"** Found Malware Config. Sending to {rabbitmq_config['exchange']} -> {rabbitmq_config['exchange_routing_key']} export queue: {result}")
                                sample_log["malor_analysis"] = result
                                try:
                                    # encoded_result = b64encode(json.dumps(sample_log).encode("utf-8"))
                                    encoded_result = json.dumps(sample_log).encode("utf-8")
                                    send_message_to_queue(channel, rabbitmq_config['exchange'], rabbitmq_config["exchange_routing_key"], encoded_result)
                                    # TODO: Fix ELK stack communication problem: Logstash gets 429 when sending messages
                                    # Controllers.notify_elk(sample_log)
                                except Exception as err:
                                    frmt_txt = traceback.format_exc()
                                    logger.info(f"ERROR: problem sending messages: {frmt_txt}")
                                    mailer.send_email(frmt_txt, "Encoding Error and message queuing")
                                    continue
                            else:
                                logger.info(f"NOT FOUND: {result}")
                else:
                    logger.info(f"File or File Path Not Found: {filepath}")
    except Exception as ex:
        frmt_txt = traceback.format_exc()
        logger.debug(frmt_txt)
    channel.basic_ack(method.delivery_tag)


if __name__ == "__main__":

    logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.info("Loaded decoders. Listening for new messages...")
    mailer = SendEmail(logger=logger)

    credentials = pika.PlainCredentials(rabbitmq_config.get("username"), rabbitmq_config.get("password"))
    parameters = pika.ConnectionParameters(rabbitmq_config.get("server_hostname"), credentials=credentials, heartbeat=300)
    connection = pika.BlockingConnection(parameters)
    channel_properties = pika.BasicProperties(content_type="application/json")
    channel = connection.channel()
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(on_message_callback=process_messages, queue=rabbitmq_config.get("input_queue"))

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    except Exception as ex:
        logger.info(ex)
        channel.stop_consuming()
