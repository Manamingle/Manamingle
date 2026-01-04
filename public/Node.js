import { MailerSend, EmailParams, Sender, Recipient } from "mailersend";

const mailerSend = new MailerSend({
    apiKey: process.env.API_KEY,
});

const sentFrom = new Sender("info@domain.com", "Your name");

const recipients = [
    new Recipient("recipient@email.com", "Your Client")
];

const personalization = [
  {
    email: "recipient@email.com",
    data: {
      CODE: ''
    },
  }
];

const emailParams = new EmailParams()
    .setFrom(sentFrom)
    .setTo(recipients)
    .setReplyTo(sentFrom)
    .setSubject("This is a Subject")
    .setTemplateId('x2p03470ww7gzdrn')
    .setPersonalization(personalization);

await mailerSend.email.send(emailParams);