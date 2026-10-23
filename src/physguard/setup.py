from setuptools import setup
import os
from glob import glob
package_name = 'physguard'
setup(
    name=package_name,
    version='0.3.0',
    packages=[package_name],
    data_files=[
        ('share/ament_index/resource_index/packages', ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
        (os.path.join('share', package_name, 'launch'), glob('launch/*.launch.py')),
        (os.path.join('share', package_name, 'rviz'), glob('rviz/*.rviz')),
        (os.path.join('share', package_name, 'worlds'), glob('worlds/*.sdf')),
        (os.path.join('share', package_name, 'tools'), glob('tools/*.py')),
        (os.path.join('share', package_name, 'urdf'), glob('urdf/*')),
        (os.path.join('share', package_name, 'config'), glob('config/*.yaml')),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='Shyam Rithin S',
    description='Cross-layer IDS for ROS 2 differential-drive robots',
    license='MIT',
    entry_points={'console_scripts': [
        'fake_robot = physguard.fake_robot:main',
        'patrol_controller = physguard.patrol_controller:main',
        'attack_injector = physguard.attack_injector:main',
        'physguard_node = physguard.physguard_node:main',
        'pure_pursuit = physguard.pure_pursuit:main',
        'track_viz = physguard.track_viz:main',
    ]},
)
