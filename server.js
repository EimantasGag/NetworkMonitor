const http = require('http');
const WebSocket = require('ws');
const { Server } = require('socket.io');
const fs = require('fs');

const server = http.createServer(function(req, res) {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  fs.readFile(__dirname + '/index.html', (err, data) => {
    if (err) {
      res.writeHead(500);
      res.end('Error loading index.html');
    } else {
      res.write(data);
      res.end();
    }
  });
});

const io = new Server(server);
// WebSocket server for Python client
const pythonWss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  if (req.url === '/python') {
    pythonWss.handleUpgrade(req, socket, head, (ws) => {
      pythonWss.emit('connection', ws, req);
    });
  } else {
    socket.destroy();
  }
});

pythonWss.on('connection', (ws) => {
  console.log('[+] Python client connected.');

  ws.on('message', (msg) => {
    //console.log('[*] From Python:', msg.toString());
    io.emit('packet', msg.toString()); // Broadcast to browser
  });

  ws.on('close', () => {
    console.log('[-] Python client disconnected.');
  });
});

server.listen(50558, () => {
  console.log('[*] Server running at http://localhost:50558');
});
