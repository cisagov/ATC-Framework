"""home module migrations/0007.py."""
# Generated by Django 4.1.3 on 2023-07-14 19:00

# Standard Python Libraries
import uuid

# Third-Party Libraries
from django.db import migrations, models


class Migration(migrations.Migration):
    """Migration class."""

    dependencies = [
        ("home", "0006_matvworgsallips_delete_vworgsallips_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="teammembers",
            name="team_member_uid",
            field=models.UUIDField(
                default=uuid.UUID("ab69feff-2278-11ee-aaa7-37ca8d677a21"),
                primary_key=True,
                serialize=False,
            ),
        ),
        migrations.AlterField(
            model_name="weeklystatuses",
            name="weekly_status_uid",
            field=models.UUIDField(
                default=uuid.UUID("ab69ff08-2278-11ee-aaa7-37ca8d677a21"),
                primary_key=True,
                serialize=False,
            ),
        ),
    ]
