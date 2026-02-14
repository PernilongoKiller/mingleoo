import os
from app import db_session, Account, User, s, mail, app, UserMessage
from sqlalchemy import func
from datetime import datetime, timedelta
from flask_mail import Message
from flask import url_for


def find_and_delete_bots(days_old=None, no_bio=False, no_avatar=False, target_username=None, target_email=None, delete=False, force=False):
    """
    Finds and optionally deletes bot accounts based on a set of criteria.

    :param days_old: The maximum age of the accounts in days.
    :param no_bio: Whether to filter by accounts with no bio.
    :param no_avatar: Whether to filter by accounts with no avatar.
    :param target_username: Specific username to filter by.
    :param target_email: Specific email to filter by.
    :param delete: Whether to delete the accounts found.
    :param force: Whether to bypass confirmation for deletion.
    """
    query = Account.query.join(User)

    if days_old is not None:
        query = query.filter(Account.created_at >= datetime.now() - timedelta(days=days_old))
    if no_bio:
        query = query.filter(User.bio == None)
    if no_avatar:
        query = query = query.filter(User.avatar_url == '/static/images/1.png')
    if target_username:
        query = query.filter(Account.username == target_username)
    if target_email:
        query = query.filter(Account.email == target_email)

    bots = query.all()

    if not bots:
        print("No accounts found matching the criteria.")
        return

    print(f"Found {len(bots)} accounts:")
    for bot in bots:
        print(f"  - Username: {bot.username}, Email: {bot.email}, Created: {bot.created_at}, Confirmed: {bot.confirmed}")

    if delete:
        if force:
            confirm_input = 'yes'
        else:
            confirm_input = input(f"Are you sure you want to delete {len(bots)} accounts? Type 'yes' to confirm: ")
        
        if confirm_input.strip().lower() == 'yes':
            print("\nDeleting accounts...")
            for bot in bots:
                db_session.delete(bot)
            db_session.commit()
            print("Accounts deleted successfully.")
        else:
            print("Deletion cancelled.")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Manage users and bots.')
    subparsers = parser.add_subparsers(dest='command')

    # Sub-parser for finding and deleting bots
    parser_bots = subparsers.add_parser('bots', help='Find and delete bots.')
    parser_bots.add_argument('--days', type=int, help='Maximum age of the accounts in days. If not specified, all ages are considered.')
    parser_bots.add_argument('--no-bio', action='store_true', help='Only show accounts with no bio.')
    parser_bots.add_argument('--no-avatar', action='store_true', help='Only show accounts with default avatar.')
    parser_bots.add_argument('--target-username', type=str, help='Specify a username to target.')
    parser_bots.add_argument('--target-email', type=str, help='Specify an email to target.')
    parser_bots.add_argument('--delete', action='store_true', help='Delete the accounts found.')
    parser_bots.add_argument('--force', action='store_true', help='Bypass confirmation for deletion.')

    args = parser.parse_args()

    if args.command == 'bots':
        find_and_delete_bots(
            days_old=args.days,
            no_bio=args.no_bio,
            no_avatar=args.no_avatar,
            target_username=args.target_username,
            target_email=args.target_email,
            delete=args.delete,
            force=args.force
        )
    else:
        parser.print_help()
