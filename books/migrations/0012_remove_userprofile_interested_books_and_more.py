# Generated by Django 4.2.1 on 2023-09-28 21:00

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('books', '0011_remove_book_borrowed_by_alter_book_status_customuser_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='interested_books',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='user',
        ),
        migrations.RemoveField(
            model_name='book',
            name='picked_up_by',
        ),
        migrations.AlterField(
            model_name='book',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='book',
            name='status',
            field=models.CharField(choices=[('available', 'Available'), ('requested', 'Requested'), ('borrowed', 'Borrowed')], default='available', max_length=20),
        ),
        migrations.DeleteModel(
            name='CustomUser',
        ),
        migrations.DeleteModel(
            name='UserProfile',
        ),
    ]