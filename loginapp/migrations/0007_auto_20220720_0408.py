# Generated by Django 2.2.7 on 2022-07-20 04:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('loginapp', '0006_auto_20220415_0806'),
    ]

    operations = [
        migrations.AlterField(
            model_name='account',
            name='role',
            field=models.CharField(choices=[('Super_Admin', 'Super Admin'), ('Company_Lead', 'Company Lead'), ('Org_Lead', 'Orgnisation Lead'), ('Dept_Lead', 'Department Lead'), ('Client_Admin', 'Client Admin'), ('Proj_Lead', 'Project Lead'), ('Team_Member', 'Team Member'), ('Hr', 'Hr'), ('User', 'User')], max_length=20),
        ),
    ]
