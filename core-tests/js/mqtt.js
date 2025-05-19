const mqtt = require('mqtt');
const port = process.argv[2];
const pino = require('pino');
const logger = pino(pino.destination('/tmp/swoole.log'));

const client = mqtt.connect(`mqtt://localhost:${port}`);

client.on('connect', () => {
    logger.info('the client is connected');

    client.subscribe('test/topic', (err) => {
        if (err) {
            console.error('subscribe fail:', err);
            return;
        }
        logger.info('subscribed: test/topic');

        client.publish('test/topic', 'Hello MQTT from Node.js!');
    });
});

client.on('disconnect', () => {
    logger.info('the client is disconnected');
    client.end()
})

client.on('message', (topic, message) => {
    logger.info(`received message, topic: ${topic}, content: ${message.toString()}`);
});

client.on('error', (err) => {
    console.error('error:', err);
});
