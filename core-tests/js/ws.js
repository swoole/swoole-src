const WebSocket = require('ws');
const pino = require('pino');
const port = process.argv[2];
const logger = pino(pino.destination('/tmp/swoole.log'));

const ws = new WebSocket(`ws://127.0.0.1:${port}/`);

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

ws.on('error', console.error);

ws.on('close', function () {
    logger.info('the node websocket client is closed');
})

ws.on('open', async () => {
    ws.send('hello', {fin: false});
    await delay(50);
    ws.send(' ', {fin: false});
    await delay(50);
    ws.send('world', {fin: true});

    await delay(200);
    ws.ping("keep alive")

    await delay(200);
    ws.close()
});

ws.on('message', function message(data) {
    logger.info('received: ' + data);
});
