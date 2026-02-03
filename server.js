const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Serve static files
app.use(express.static(__dirname));

// Game rooms management
const rooms = new Map();
const waitingPlayers = [];

class GameRoom {
    constructor(id) {
        this.id = id;
        this.players = [];
        this.gameState = {
            players: [],
            bullets: [],
            items: [],
            obstacles: []
        };
        this.started = false;
    }

    addPlayer(client) {
        if (this.players.length >= 2) return false;
        
        const playerId = this.players.length + 1;
        this.players.push({
            client: client,
            id: playerId,
            ready: false
        });

        client.roomId = this.id;
        client.playerId = playerId;

        return true;
    }

    broadcast(message, exceptClient = null) {
        this.players.forEach(p => {
            if (p.client !== exceptClient && p.client.readyState === WebSocket.OPEN) {
                p.client.send(JSON.stringify(message));
            }
        });
    }

    removePlayer(client) {
        this.players = this.players.filter(p => p.client !== client);
        
        // Notify other player
        this.broadcast({
            type: 'player_left',
            message: 'Đối thủ đã rời phòng'
        });

        return this.players.length === 0;
    }

    startGame() {
        if (this.players.length !== 2) return;
        
        this.started = true;
        
        // Initialize game state
        this.gameState = {
            players: [
                { id: 1, x: 50, y: 50, color: '#4facfe', hp: 5, mag: 10, ammo: 30, dirX: 0, dirY: 0 },
                { id: 2, x: 700, y: 500, color: '#ff0844', hp: 5, mag: 10, ammo: 30, dirX: 0, dirY: 0 }
            ],
            bullets: [],
            items: [],
            obstacles: this.generateObstacles()
        };

        // Send start signal to both players
        this.players.forEach((p, index) => {
            p.client.send(JSON.stringify({
                type: 'game_start',
                playerId: p.id,
                gameState: this.gameState
            }));
        });

        // Spawn initial items
        this.spawnItem('HP');
        this.spawnItem('AMMO');
        this.spawnItem('AMMO');
    }

    generateObstacles() {
        const obstacles = [];
        for (let i = 0; i < 8; i++) {
            obstacles.push({
                x: 100 + Math.random() * 600,
                y: 100 + Math.random() * 400,
                w: 60, 
                h: 60
            });
        }
        return obstacles;
    }

    spawnItem(type) {
        const item = {
            type: type,
            x: 50 + Math.random() * 700,
            y: 50 + Math.random() * 500,
            size: 20,
            id: Date.now() + Math.random()
        };
        this.gameState.items.push(item);
        
        this.broadcast({
            type: 'item_spawn',
            item: item
        });
    }
}

// WebSocket connection handling
wss.on('connection', (ws) => {
    console.log('New client connected');

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);

            switch (data.type) {
                case 'find_match':
                    handleFindMatch(ws, data);
                    break;

                case 'player_update':
                    handlePlayerUpdate(ws, data);
                    break;

                case 'shoot':
                    handleShoot(ws, data);
                    break;

                case 'reload':
                    handleReload(ws, data);
                    break;

                case 'item_collect':
                    handleItemCollect(ws, data);
                    break;

                case 'player_hit':
                    handlePlayerHit(ws, data);
                    break;
            }
        } catch (error) {
            console.error('Error handling message:', error);
        }
    });

    ws.on('close', () => {
        console.log('Client disconnected');
        handleDisconnect(ws);
    });
});

function handleFindMatch(ws, data) {
    // Try to find existing waiting player
    if (waitingPlayers.length > 0) {
        const opponent = waitingPlayers.shift();
        
        // Create new room
        const roomId = `room_${Date.now()}`;
        const room = new GameRoom(roomId);
        rooms.set(roomId, room);

        room.addPlayer(opponent);
        room.addPlayer(ws);

        // Notify both players
        opponent.send(JSON.stringify({
            type: 'match_found',
            roomId: roomId,
            playerId: 1
        }));

        ws.send(JSON.stringify({
            type: 'match_found',
            roomId: roomId,
            playerId: 2
        }));

        // Start game after 2 seconds
        setTimeout(() => {
            room.startGame();
        }, 2000);

    } else {
        // Add to waiting list
        waitingPlayers.push(ws);
        ws.send(JSON.stringify({
            type: 'waiting',
            message: 'Đang tìm đối thủ...'
        }));
    }
}

function handlePlayerUpdate(ws, data) {
    const room = rooms.get(ws.roomId);
    if (!room) return;

    // Broadcast to other player
    room.broadcast({
        type: 'opponent_update',
        playerId: data.playerId,
        x: data.x,
        y: data.y,
        dirX: data.dirX,
        dirY: data.dirY,
        hp: data.hp,
        mag: data.mag,
        ammo: data.ammo,
        reloading: data.reloading
    }, ws);
}

function handleShoot(ws, data) {
    const room = rooms.get(ws.roomId);
    if (!room) return;

    room.broadcast({
        type: 'opponent_shoot',
        bullet: data.bullet
    }, ws);
}

function handleReload(ws, data) {
    const room = rooms.get(ws.roomId);
    if (!room) return;

    room.broadcast({
        type: 'opponent_reload',
        playerId: data.playerId
    }, ws);
}

function handleItemCollect(ws, data) {
    const room = rooms.get(ws.roomId);
    if (!room) return;

    // Remove item from game state
    room.gameState.items = room.gameState.items.filter(i => i.id !== data.itemId);

    room.broadcast({
        type: 'item_collected',
        itemId: data.itemId,
        playerId: data.playerId
    }, ws);
}

function handlePlayerHit(ws, data) {
    const room = rooms.get(ws.roomId);
    if (!room) return;

    room.broadcast({
        type: 'player_damaged',
        playerId: data.targetId,
        hp: data.hp
    }, ws);

    // Check for game over
    if (data.hp <= 0) {
        room.broadcast({
            type: 'game_over',
            winnerId: data.playerId
        });
    }
}

function handleDisconnect(ws) {
    // Remove from waiting list
    const waitingIndex = waitingPlayers.indexOf(ws);
    if (waitingIndex > -1) {
        waitingPlayers.splice(waitingIndex, 1);
    }

    // Remove from room
    if (ws.roomId) {
        const room = rooms.get(ws.roomId);
        if (room) {
            const isEmpty = room.removePlayer(ws);
            if (isEmpty) {
                rooms.delete(ws.roomId);
            }
        }
    }
}

// Spawn items periodically
setInterval(() => {
    rooms.forEach(room => {
        if (room.started && Math.random() > 0.5) {
            room.spawnItem(Math.random() > 0.5 ? 'HP' : 'AMMO');
        }
    });
}, 5000);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🎮 Server đang chạy tại http://localhost:${PORT}`);
    console.log(`📡 WebSocket server sẵn sàng!`);
});
