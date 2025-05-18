# backend/app/services/email.py
from fastapi import BackgroundTasks
from ..config import settings


def send_password_reset_email(email: str, token: str):
    # In production, use SendGrid, Mailgun, etc.
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    print(f"Sending password reset email to {email}")
    print(f"Reset URL: {reset_url}")
    # Actual email sending implementation would go here
    
    
    
# # backend/app/services/email.py
# import os
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail, From, To, Subject, HtmlContent
# from fastapi import BackgroundTasks, HTTPException
# from typing import Optional

# from ..config import settings
# from ..core.logger import logger


# class EmailService:
#     def __init__(self):
#         self.sg = SendGridAPIClient(api_key=settings.SENDGRID_API_KEY)
#         self.from_email = From(settings.SENDGRID_FROM_EMAIL, settings.COMPANY_NAME)

#     async def send_email(
#         self,
#         to_email: str,
#         subject: str,
#         html_content: str,
#         background_tasks: Optional[BackgroundTasks] = None,
#     ):
#         message = Mail(
#             from_email=self.from_email,
#             to_emails=To(to_email),
#             subject=Subject(subject),
#             html_content=HtmlContent(html_content),
#         )

#         if background_tasks:
#             background_tasks.add_task(self._send_async, message)
#         else:
#             await self._send_async(message)

#     async def _send_async(self, message: Mail):
#         try:
#             response = self.sg.send(message)
#             if response.status_code not in [200, 202]:
#                 logger.error(f"Email failed to send: {response.body}")
#                 raise HTTPException(status_code=500, detail="Failed to send email")
#             logger.info(f"Email sent successfully to {message.to}")
#         except Exception as e:
#             logger.error(f"Email sending error: {str(e)}")
#             raise HTTPException(status_code=500, detail="Email service unavailable")


# email_service = EmailService()


# def send_password_reset_email(
#     email: str, token: str, background_tasks: BackgroundTasks
# ):
#     reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"

#     subject = f"{settings.COMPANY_NAME} - Password Reset Request"
#     html_content = f"""
#     <html>
#         <body>
#             <h2>Password Reset Request</h2>
#             <p>You requested a password reset for your {settings.COMPANY_NAME} account.</p>
#             <p>Click <a href="{reset_url}">here</a> to reset your password.</p>
#             <p>This link will expire in 24 hours.</p>
#             <p>If you didn't request this, please ignore this email.</p>
#             <br/>
#             <p>Best regards,</p>
#             <p>The {settings.COMPANY_NAME} Team</p>
#         </body>
#     </html>
#     """

#     email_service.send_email(
#         to_email=email,
#         subject=subject,
#         html_content=html_content,
#         background_tasks=background_tasks,
#     )


# def send_welcome_email(email: str, username: str, background_tasks: BackgroundTasks):
#     subject = f"Welcome to {settings.COMPANY_NAME}"
#     html_content = f"""
#     <html>
#         <body>
#             <h2>Welcome to {settings.COMPANY_NAME}, {username}!</h2>
#             <p>Your account has been successfully created.</p>
#             <p>You can now login to your account and start using our security monitoring system.</p>
#             <br/>
#             <p>Best regards,</p>
#             <p>The {settings.COMPANY_NAME} Team</p>
#         </body>
#     </html>
#     """

#     email_service.send_email(
#         to_email=email,
#         subject=subject,
#         html_content=html_content,
#         background_tasks=background_tasks,
#     )

