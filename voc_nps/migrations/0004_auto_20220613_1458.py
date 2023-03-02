# Generated by Django 2.2.7 on 2022-06-13 14:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('voc_nps', '0003_rating'),
    ]

    operations = [
        migrations.CreateModel(
            name='Scale',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('maintext', models.CharField(blank=True, max_length=250, null=True)),
            ],
            options={
                'db_table': 'Scale',
            },
        ),
        migrations.AlterField(
            model_name='rating',
            name='text',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
    ]
