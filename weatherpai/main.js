const { getWeather, getMap, getForecast } = require('./parseService.js');
const bodyParser = require('body-parser')
const path = require('path')

const express = require('express')
const app = express()
const http = require('http')
const server = http.createServer(app)

app.use(bodyParser.urlencoded({extended: true}))
app.use(express.static(path.join(__dirname + `/views/static`)))
app.set('view engine', 'ejs')

app.get(`/`, async(req, res) => {
    res.render('index')
})

app.post(`/`, async(req, res) => {
    const city = req.body.city
    res.redirect(`/weather?city=${city}`)
})

app.get(`/weather`, async (req, res) => {
    try {
      const [weatherData, forecastData] = await Promise.all([
        getWeather(req.query.city),
        getForecast(req.query.city),
      ]);
      console.log(weatherData )
      const mapImage = await getMap(weatherData.coord.lon, weatherData.coord.lat)
      if (weatherData) {
        res.render('weather', { weather: weatherData, map: mapImage, forecast: forecastData });
      } else {
        res.redirect(`/`);
      }
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  });

app.listen(process.env.PORT, () => {
    console.log(`server running on port :${process.env.PORT}`)
})