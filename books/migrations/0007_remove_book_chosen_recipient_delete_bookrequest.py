# Generated by Django 4.2.5 on 2023-09-28 19:01

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('books', '0006_remove_bookrequest_created_at_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='book',
            name='chosen_recipient',
        ),
        migrations.DeleteModel(
            name='BookRequest',
        ),
    ]
