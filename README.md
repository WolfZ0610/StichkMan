# 🎮 Stickman Arena Online - Multiplayer Shooter

Game bắn súng người que đối kháng online theo thời gian thực sử dụng WebSocket!

## ✨ Tính năng

- ⚔️ **Multiplayer Online**: Chơi với người khác qua mạng
- 🤖 **Offline Mode**: Chơi với AI khi không có mạng
- 🎯 **Kéo chuột để bắn**: Giữ chuột để tích lực, thả để bắn xa hơn
- 🔫 **Hệ thống nạp đạn**: Quản lý băng đạn và đạn dự trữ
- 🏥 **Vật phẩm hỗ trợ**: HP và đạn xuất hiện ngẫu nhiên
- 🧱 **Chướng ngại vật**: Rào chắn tạo chiến thuật

## 📦 Cài đặt

### Yêu cầu
- Node.js 14+ ([Tải tại đây](https://nodejs.org/))

### Bước 1: Cài đặt dependencies
```bash
npm install
```

### Bước 2: Chạy server
```bash
npm start
```

Hoặc dùng nodemon để tự động restart khi code thay đổi:
```bash
npm run dev
```

## 🚀 Cách chơi

1. Mở trình duyệt và truy cập: `http://localhost:3000`
2. Chọn **"TÌM TRẬN ĐẤU ONLINE"** để chơi với người khác
3. Hoặc chọn **"Chơi Offline"** để chơi với AI

### 🎮 Điều khiển
- **Di chuyển**: W, A, S, D
- **Bắn**: Giữ chuột trái và kéo để tích lực, thả để bắn
- **Nạp đạn**: Phím R
- **Bắn nhanh**: Space (bắn theo hướng di chuyển)

## 🌐 Deploy lên Internet

### Option 1: Heroku
```bash
# Cài Heroku CLI
npm install -g heroku

# Login và tạo app
heroku login
heroku create ten-game-cua-ban

# Deploy
git init
git add .
git commit -m "Initial commit"
git push heroku main
```

### Option 2: Render.com
1. Tạo tài khoản tại [render.com](https://render.com)
2. Tạo **Web Service** mới
3. Kết nối với GitHub repo của bạn
4. Build Command: `npm install`
5. Start Command: `npm start`
6. Deploy!

### Option 3: Railway.app
1. Tạo tài khoản tại [railway.app](https://railway.app)
2. Tạo project mới từ GitHub
3. Railway tự động detect và deploy

## 🔧 Cấu hình

### Thay đổi Port
Mặc định server chạy trên port 3000. Để đổi port:

```bash
PORT=8080 npm start
```

Hoặc sửa trong file `server.js`:
```javascript
const PORT = process.env.PORT || 3000;
```

### Tùy chỉnh game
Sửa các constant trong `index.html`:
- `MAG_SIZE`: Số đạn trong băng (mặc định: 10)
- `RELOAD_TIME`: Thời gian nạp đạn ms (mặc định: 1500)
- `PLAYER_SPEED`: Tốc độ di chuyển (mặc định: 4)
- `MAX_CHARGE_TIME`: Thời gian tích lực tối đa (mặc định: 2000)

## 📝 Cấu trúc File

```
stickman-arena-online/
├── server.js          # WebSocket server + matchmaking
├── index.html         # Game client (HTML + CSS + JS)
├── package.json       # Dependencies
└── README.md          # Hướng dẫn này
```

## 🐛 Troubleshooting

### Không kết nối được server
- Kiểm tra server đang chạy: `npm start`
- Kiểm tra port 3000 chưa bị chiếm bởi app khác
- Tắt firewall/antivirus tạm thời

### Lag khi chơi online
- Giảm tần suất gửi update (sửa trong `index.html`)
- Chơi trên mạng tốt hơn

### Không tìm thấy đối thủ
- Cần ít nhất 2 người cùng vào để ghép trận
- Thử chế độ Offline để test

## 🎯 Roadmap

- [ ] Thêm chat trong game
- [ ] Ranking system
- [ ] Nhiều map hơn
- [ ] Nhiều loại vũ khí
- [ ] Spectator mode
- [ ] Replay system

## 📄 License

MIT License - Tự do sử dụng và chỉnh sửa!

---

Made with ❤️ by Claude
