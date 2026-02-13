#!/usr/bin/env python3
"""
Blazar Reservation Splitter Sidecar for Ceilometer

This sidecar intercepts Blazar 'start_lease' events from RabbitMQ,
splits out individual reservations from the payload, and publishes
separate notification events for each reservation to Ceilometer.

This enables Ceilometer to create individual Gnocchi metrics for
each reservation in a lease, rather than just the first one.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Any

import pika
from oslo_config import cfg

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('blazar-reservation-splitter')

# Configuration options
CONF = cfg.CONF

opts = [
    cfg.StrOpt('rabbitmq_host',
               default=os.getenv('RABBITMQ_HOST', 'rabbitmq.openstack.svc.cluster.local'),
               help='RabbitMQ host'),
    cfg.IntOpt('rabbitmq_port',
               default=int(os.getenv('RABBITMQ_PORT', '5672')),
               help='RabbitMQ port'),
    cfg.StrOpt('rabbitmq_user',
               default=os.getenv('RABBITMQ_USER', 'rabbitmq'),
               help='RabbitMQ username'),
    cfg.StrOpt('rabbitmq_password',
               default=os.getenv('RABBITMQ_PASSWORD', 'password'),
               help='RabbitMQ password'),
    cfg.StrOpt('rabbitmq_vhost',
               default=os.getenv('RABBITMQ_VHOST', '/'),
               help='RabbitMQ vhost (default vhost used by OpenStack)'),
    cfg.StrOpt('exchange',
               default=os.getenv('EXCHANGE', 'openstack'),
               help='OpenStack exchange name'),
    cfg.StrOpt('queue',
               default=os.getenv('QUEUE', 'blazar_reservation_splitter'),
               help='Queue name for this sidecar'),
    cfg.ListOpt('target_events',
                default=['lease.event.start_lease'],
                help='List of Blazar events to intercept'),
]

CONF.register_opts(opts)


class BlazarReservationSplitter:
    """Intercepts Blazar events and splits reservations into individual metrics."""

    def __init__(self):
        self.connection = None
        self.channel = None
        self.processed_count = 0
        self.error_count = 0

    def connect_rabbitmq(self):
        """Establish connection to RabbitMQ (same instance used by OpenStack services)."""
        credentials = pika.PlainCredentials(
            CONF.rabbitmq_user,
            CONF.rabbitmq_password
        )

        # Connection parameters - using the same RabbitMQ as OpenStack services
        params = pika.ConnectionParameters(
            host=CONF.rabbitmq_host,
            port=CONF.rabbitmq_port,
            virtual_host=CONF.rabbitmq_vhost,
            credentials=credentials,
            heartbeat=600,
            blocked_connection_timeout=300,
        )

        logger.info(f"Connecting to RabbitMQ: {CONF.rabbitmq_host}:{CONF.rabbitmq_port}{CONF.rabbitmq_vhost}")
        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()

        # Declare queue and bind to OpenStack exchange
        self.channel.queue_declare(queue=CONF.queue, durable=True)
        
        # Bind to specific event types on the OpenStack exchange
        for event_type in CONF.target_events:
            routing_key = f"notifications.info"
            self.channel.queue_bind(
                exchange=CONF.exchange,
                queue=CONF.queue,
                routing_key=routing_key
            )
            logger.info(f"Bound to exchange '{CONF.exchange}' with routing key: {routing_key}")

        logger.info("RabbitMQ connection established successfully")

    def split_reservations(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Split reservations from the lease payload into individual notification payloads.
        
        Args:
            payload: Original Blazar lease payload
            
        Returns:
            List of individual reservation payloads
        """
        reservations = payload.get('reservations', [])
        if not reservations:
            logger.warning(f"No reservations found in lease {payload.get('lease_id')}")
            return []

        individual_payloads = []
        
        for reservation in reservations:
            # Create a new payload for each reservation
            reservation_payload = {
                # Lease context
                'lease_id': payload.get('lease_id'),
                'lease_name': payload.get('name'),
                'user_id': payload.get('user_id'),
                'project_id': payload.get('project_id'),
                'trust_id': payload.get('trust_id'),
                'start_date': payload.get('start_date'),
                'end_date': payload.get('end_date'),
                'lease_status': payload.get('status'),
                'degraded': payload.get('degraded'),
                
                # Reservation details
                'reservation_id': reservation.get('id'),
                'resource_id': reservation.get('resource_id'),
                'resource_type': reservation.get('resource_type'),
                'reservation_status': reservation.get('status'),
                'missing_resources': reservation.get('missing_resources'),
                'resources_changed': reservation.get('resources_changed'),
                'created_at': reservation.get('created_at'),
                'updated_at': reservation.get('updated_at'),
            }
            
            # Add resource-type specific fields
            resource_type = reservation.get('resource_type', '')
            
            if resource_type == 'flavor:instance':
                reservation_payload.update({
                    'vcpus': reservation.get('vcpus'),
                    'memory_mb': reservation.get('memory_mb'),
                    'disk_gb': reservation.get('disk_gb'),
                    'amount': reservation.get('amount'),
                    'affinity': reservation.get('affinity'),
                    'resource_properties': reservation.get('resource_properties'),
                    'flavor_id': reservation.get('flavor_id'),
                    'aggregate_id': reservation.get('aggregate_id'),
                    'server_group_id': reservation.get('server_group_id'),
                })
            elif resource_type == 'physical:host':
                reservation_payload.update({
                    'hypervisor_properties': reservation.get('hypervisor_properties'),
                    'resource_properties': reservation.get('resource_properties'),
                    'before_end': reservation.get('before_end'),
                    'min': reservation.get('min'),
                    'max': reservation.get('max'),
                })
            elif resource_type == 'virtual:floatingip':
                reservation_payload.update({
                    'amount': reservation.get('amount'),
                    'network_id': reservation.get('network_id'),
                })
            
            individual_payloads.append(reservation_payload)
            
        logger.info(f"Split lease {payload.get('lease_id')} into {len(individual_payloads)} reservation payloads")
        return individual_payloads

    def publish_reservation_event(self, reservation_payload: Dict[str, Any], event_type: str):
        """
        Publish an individual reservation event back to the same OpenStack exchange.
        
        Args:
            reservation_payload: Individual reservation payload
            event_type: Event type (e.g., 'blazar.reservation.start')
        """
        resource_type = reservation_payload.get('resource_type', 'unknown')
        
        # Determine the specific event type based on resource type
        if resource_type == 'flavor:instance':
            specific_event_type = f"{event_type}.flavor_instance"
        elif resource_type == 'physical:host':
            specific_event_type = f"{event_type}.physical_host"
        elif resource_type == 'virtual:floatingip':
            specific_event_type = f"{event_type}.virtual_floatingip"
        
        # Create Oslo notification message format
        message = {
                'oslo.version': '2.0',
                'oslo.message': json.dumps({
                'event_type': specific_event_type,
                'timestamp': datetime.utcnow().isoformat(),
                'message_id': f"{reservation_payload['reservation_id']}-{int(time.time())}",
                'priority': 'INFO',
                'publisher_id': 'blazar-reservation-splitter',
                'payload': reservation_payload,
            })
        }
        
        # Publish back to the same OpenStack exchange
        routing_key = f"notifications.info"
        
        try:
            self.channel.basic_publish(
                exchange=CONF.exchange,
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Persistent
                    content_type='application/json',
                )
            )
            logger.debug(f"Published {specific_event_type} for reservation {reservation_payload['reservation_id']}")
        except Exception as e:
            logger.error(f"Failed to publish reservation event: {e}")
            raise

    def process_message(self, ch, method, properties, body):
        """
        Process incoming Blazar notification message.
        
        Args:
            ch: Channel
            method: Delivery method
            properties: Message properties
            body: Message body
        """
        try:
            # Parse the message
            message = json.loads(body)
            
            # Extract Oslo message format
            if 'oslo.message' in message:
                oslo_message = json.loads(message['oslo.message'])
            else:
                oslo_message = message
            
            event_type = oslo_message.get('event_type')
            payload = oslo_message.get('payload', {})
            
            # Only process target events ('lease.event.start_lease')
            if event_type not in CONF.target_events:
                logger.debug(f"Skipping event: {event_type} (not in target events: {CONF.target_events})")
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return

            logger.info(f"Processing event: {event_type} for lease {payload.get('lease_id')}")
            
            # Split reservations
            reservation_payloads = self.split_reservations(payload)
            
            # Publish individual reservation events
            for reservation_payload in reservation_payloads:
                self.publish_reservation_event(
                    reservation_payload,
                    'blazar.reservation'
                )
            
            # Acknowledge the message
            ch.basic_ack(delivery_tag=method.delivery_tag)
            self.processed_count += 1
            
            logger.info(f"Successfully processed {len(reservation_payloads)} reservations from lease {payload.get('lease_id')}")
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message JSON: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            self.error_count += 1
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            self.error_count += 1

    def start_consuming(self):
        """Start consuming messages from the queue."""
        logger.info(f"Starting to consume from queue: {CONF.queue}")
        logger.info(f"Listening for events: {CONF.target_events}")
        
        # Set QoS
        self.channel.basic_qos(prefetch_count=1)
        
        # Start consuming
        self.channel.basic_consume(
            queue=CONF.queue,
            on_message_callback=self.process_message
        )
        
        try:
            self.channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
            self.stop()
        except Exception as e:
            logger.error(f"Error in consumer loop: {e}", exc_info=True)
            raise

    def stop(self):
        """Stop consuming and close connections."""
        logger.info(f"Shutting down. Processed: {self.processed_count}, Errors: {self.error_count}")
        
        if self.channel and self.channel.is_open:
            self.channel.stop_consuming()
            self.channel.close()
        
        if self.connection and self.connection.is_open:
            self.connection.close()
        
        logger.info("Shutdown complete")

    def run(self):
        """Main run loop with reconnection logic."""
        retry_delay = 5
        max_retry_delay = 60
        
        while True:
            try:
                self.connect_rabbitmq()
                self.start_consuming()
            except pika.exceptions.AMQPConnectionError as e:
                logger.error(f"Connection error: {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                time.sleep(retry_delay)
            finally:
                self.stop()


def main():
    """Main entry point."""
    try:
        CONF(sys.argv[1:])
        
        logger.info("=" * 60)
        logger.info("Blazar Reservation Splitter Sidecar Starting")
        logger.info("=" * 60)
        logger.info(f"RabbitMQ Host: {CONF.rabbitmq_host}:{CONF.rabbitmq_port}")
        logger.info(f"RabbitMQ vhost: {CONF.rabbitmq_vhost}")
        logger.info(f"Exchange: {CONF.exchange}")
        logger.info(f"Queue: {CONF.queue}")
        logger.info(f"Target events: {CONF.target_events}")
        logger.info("=" * 60)
        
        splitter = BlazarReservationSplitter()
        splitter.run()
        
    except KeyboardInterrupt:
        logger.info("Received interrupt, exiting...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

