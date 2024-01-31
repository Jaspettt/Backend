require('dotenv').config()
const axios = require('axios');
const { properDate, getIconURL, degreesToDirection, properTime } = require('./prettier');


const getWeather = async(city) => {
  const key = process.env.API_KEY
  const url = `https://api.openweathermap.org/data/2.5/weather?q=${city}&appid=${key}`
  const response = await axios.get(url)
    .then(response => response.data)
    .catch(error => console.log(error))
  if (response) {
    response.weather[0].iconURL = getIconURL(response.weather[0].icon)
  }
  return response
}

const getMap = async(lon, lat) => {
  const key = process.env.GEO_API_KEY
  const url = `https://maps.geoapify.com/v1/staticmap?style=osm-bright-smooth&width=1160&height=400&center=lonlat:${lon},${lat}&zoom=11.7&apiKey=${key}`;
  const response = await axios.get(url, { responseType: 'arraybuffer' })
    .then(response => response.data)
    .catch(error => console.log(error))
  const base64Image = Buffer.from(response, 'binary').toString('base64');
  const imageUrl = `data:image/png;base64,${base64Image}`;
  return imageUrl
}

const getForecast = async(city) => {
  const key = process.env.API_KEY
  const url = `https://api.openweathermap.org/data/2.5/forecast/daily?q=${city}&cnt=14&appid=${key}`
  const response = await axios.get(url)
    .then(response => response.data)
    .catch(error => console.log(error))
  response.list.forEach(elem => {
    elem.dt = properDate(elem.dt)
    elem.weather[0].iconURL = getIconURL(elem.weather[0].icon)
    elem.deg = degreesToDirection(elem.deg)
    elem.sunrise = properTime(elem.sunrise)
    elem.sunset = properTime(elem.sunset)
  })
  return response
}

module.exports = { 
  getWeather, 
  getMap, 
  getForecast 
};