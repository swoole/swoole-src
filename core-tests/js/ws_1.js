const WebSocket = require('ws');
const pino = require('pino');
const port = process.argv[2];
const logger = pino(pino.destination('/tmp/swoole.log'));

const ws_1 = new WebSocket(`ws://127.0.0.1:${port}/`);

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

ws_1.on('error', console.error);

ws_1.on('close', function () {
    logger.info('the node websocket client is closed');
})

ws_1.on('open', async () => {
    ws_1.send('hello', {fin: false});
    await delay(50);
    ws_1.send(' ', {fin: false});
    await delay(50);
    ws_1.send('world', {fin: true});

    await delay(200);
    ws_1.ping("keep alive")

    await delay(200);
    ws_1.close()
});

ws_1.on('message', function message(data) {
    logger.info('received: ' + data);
});
