import random
import requests

class MFAService:
    @staticmethod
    def generate_otp():
        """
        Generates a 6-digit One-Time Password (OTP).

        :return: A string representing a 6-digit OTP.
        """
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])

    @staticmethod
    def send_sms_otp(recipient, otp):
        """
        Sends the OTP to the specified recipient via SMS using an external SMS service.

        :param recipient: The phone number of the recipient, in the format "05XXXXXXXX".
        :param otp: The One-Time Password to send.

        :return: The response from the SMS service API.
        """
        url = "https://api.sms4free.co.il/ApiSMS/v2/SendSMS"
        data = {
            "key": Config.sms_key,
            "user": Config.sms_user,
            "sender": "Elidor",
            "pass": Config.sms_pass,
            "recipient": recipient,
            "msg": f"Your OTP is: {otp}"
        }

        response = requests.post(url, json=data)
        # Gives you indication on how many recipients the message was sent to and if it was successful
        print(response.text)
        return response

    @staticmethod
    def generate_session_id():
        """
        Generates a 16-digit session ID.

        :return: A string representing a 16-digit session ID.
        """
        return ''.join([str(random.randint(0, 9)) for _ in range(16)])
