# Generated by Django 2.2.7 on 2022-04-13 13:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('loginapp', '0002_account_phonecode'),
    ]

    operations = [
        migrations.CreateModel(
            name='GuestAccount',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=20, unique=True)),
                ('email', models.CharField(max_length=30)),
                ('is_activated', models.BooleanField()),
                ('otp', models.IntegerField(null=True)),
                ('token', models.CharField(max_length=300)),
            ],
            options={
                'db_table': 'GuestAccount',
            },
        ),
    ]
