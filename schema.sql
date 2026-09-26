-- LedgerX billing schema
-- Run this once in your Supabase project: Dashboard → SQL Editor → paste → Run.

-- One row per signed-up user, auto-created on signup.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  plan text not null default 'base' check (plan in ('base','pro','quant')),
  status text not null default 'inactive' check (status in ('inactive','active','cancelled','suspended','past_due')),
  paypal_subscription_id text unique,
  current_period_end timestamptz,
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- A signed-in user can read their own row (this is how the app knows the plan).
create policy "read own profile" on public.profiles
  for select
  using (auth.uid() = id);

-- Deliberately no insert/update/delete policy for the 'authenticated' role.
-- The only way to change plan/status is the service-role key, which only the
-- paypal-webhook Edge Function holds. This is what makes the plan trustworthy:
-- a user editing their own browser cannot upgrade themselves.

-- Auto-create a profile row the moment someone signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Helpful index for the webhook to look a subscriber up by PayPal subscription id.
create index if not exists profiles_paypal_subscription_id_idx
  on public.profiles (paypal_subscription_id);
