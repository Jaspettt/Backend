const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: "smtp.yandex.ru",
    port: 465,
    secure: true,
    auth: {
        user: "javaprojectSE@yandex.ru",
        pass: "57UtPapGdeGrduG"
    }
});

function sendEmail(toEmail, text) {
    const mailOptions = {
        from: 'javaprojectSE@yandex.ru',
        to: toEmail,
        subject: 'Web Final project',
        text: text
    };

    transporter.sendMail(mailOptions, function(error, info){
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

module.exports = sendEmail;
