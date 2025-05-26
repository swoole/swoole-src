const WebSocket = require('ws');
const pino = require('pino');
const port = process.argv[2];
const logger = pino(pino.destination('/tmp/swoole.log'));

const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/close`);

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

ws.on('error', console.error);

ws.on('close', function (code, reason) {
    logger.info('the node websocket client is closed, code: ' + code + ', reason: ' + reason.toString());
})

ws.on('open', async () => {
});

ws.on('message', function message(data) {
});
