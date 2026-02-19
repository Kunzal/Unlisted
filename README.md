# Unlisted India — Pre-IPO Share Price Aggregator

Live platform tracking unlisted / pre-IPO share prices across multiple dealers.

## Features
- Real-time price aggregation from 5 sources
- Buy/Sell OTC inquiry form
- User authentication & watchlist
- Admin dashboard

## Tech Stack
- **Backend**: Node.js + Express
- **Database**: MongoDB
- **Frontend**: Vanilla HTML/CSS/JS

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MONGODB_URI` | MongoDB Atlas connection string |
| `JWT_SECRET` | Random secret string for JWT tokens |
| `PORT` | Server port (default: 5000) |
| `NODE_ENV` | Set to `production` |

## Default Admin
- Email: `admin@unlisted.in`
- Password: `Admin@12345`

> Change admin password after first login!
