const properDate = (timestamp) => {
    const months = {
        1: "Jan",
        2: "Feb",
        3: "Mar",
        4: "Apr",
        5: "May",
        6: "Jun",
        7: "Jul",
        8: "Aug",
        9: "Sep",
        10: "Oct",
        11: "Nov",
        12: "Dec"
      };
    const dateObject = new Date(timestamp * 1000)
    return `${dateObject.getDate()} ${months[dateObject.getMonth() + 1]}`
}

const properTime = (timestamp) => {
    const timeObject = new Date(timestamp * 1000)
    let hrs = timeObject.getHours()
    let mnts = timeObject.getMinutes() < 10 ? `0${timeObject.getMinutes()}` : timeObject.getMinutes()
    return `${hrs}:${mnts}`
}

const degreesToDirection = (degrees) => {
    degrees = (degrees % 360 + 360) % 360;

    if (degrees >= 337.5 || degrees < 22.5) {
        return "N";
    } else if (degrees >= 22.5 && degrees < 67.5) {
        return "NE";
    } else if (degrees >= 67.5 && degrees < 112.5) {
        return "E";
    } else if (degrees >= 112.5 && degrees < 157.5) {
        return "SE";
    } else if (degrees >= 157.5 && degrees < 202.5) {
        return "S";
    } else if (degrees >= 202.5 && degrees < 247.5) {
        return "SW";
    } else if (degrees >= 247.5 && degrees < 292.5) {
        return "W";
    } else {
        return "NW";
    }
}

const getIconURL = (icon) => {
    return `https://openweathermap.org/img/wn/${icon}@2x.png`
}

module.exports = {
    degreesToDirection, 
    properDate,
    getIconURL,
    properTime
}