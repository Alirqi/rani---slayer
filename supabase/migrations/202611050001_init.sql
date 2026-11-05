-- RANI SLAYER: secure initial schema
-- Apply this migration in the Supabase SQL Editor before connecting the storefront.

create extension if not exists pgcrypto;

create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  slug text not null unique,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  category_id uuid references public.categories(id) on delete set null,
  name text not null check (char_length(name) between 1 and 160),
  description text not null default '',
  price_yer numeric(12,2) not null check (price_yer >= 0),
  stock integer not null default 0 check (stock >= 0),
  image_url text,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_name text not null check (char_length(customer_name) between 2 and 120),
  phone text not null check (char_length(phone) between 7 and 25),
  address text not null check (char_length(address) between 4 and 500),
  status text not null default 'pending'
    check (status in ('pending','confirmed','processing','shipped','completed','cancelled')),
  total_yer numeric(12,2) not null default 0 check (total_yer >= 0),
  created_at timestamptz not null default now()
);

create table if not exists public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  product_name text not null,
  unit_price_yer numeric(12,2) not null check (unit_price_yer >= 0),
  quantity integer not null check (quantity between 1 and 20),
  line_total_yer numeric(12,2) not null check (line_total_yer >= 0)
);

create index if not exists products_active_idx on public.products(is_active);
create index if not exists products_category_idx on public.products(category_id);
create index if not exists orders_created_idx on public.orders(created_at desc);
create index if not exists order_items_order_idx on public.order_items(order_id);

-- Admin membership is maintained only by the project owner/service role.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.admin_users
    where user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

alter table public.categories enable row level security;
alter table public.products enable row level security;
alter table public.admin_users enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;

drop policy if exists "Public reads active categories" on public.categories;
create policy "Public reads active categories"
  on public.categories for select to anon, authenticated
  using (is_active = true);

drop policy if exists "Admins manage categories" on public.categories;
create policy "Admins manage categories"
  on public.categories for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "Public reads active products" on public.products;
create policy "Public reads active products"
  on public.products for select to anon, authenticated
  using (is_active = true);

drop policy if exists "Admins manage products" on public.products;
create policy "Admins manage products"
  on public.products for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "Admins read own admin membership" on public.admin_users;
create policy "Admins read own admin membership"
  on public.admin_users for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists "Admins read orders" on public.orders;
create policy "Admins read orders"
  on public.orders for select to authenticated
  using (public.is_admin());

drop policy if exists "Admins read order items" on public.order_items;
create policy "Admins read order items"
  on public.order_items for select to authenticated
  using (public.is_admin());

grant select on public.categories, public.products to anon, authenticated;
grant insert, update, delete on public.categories, public.products to authenticated;
grant select on public.admin_users, public.orders, public.order_items to authenticated;

-- Order creation is server-only. Call it from a Supabase Edge Function that
-- validates input, applies CAPTCHA/rate limits, and uses the service-role key
-- from server-side secrets. Never put that key in index.html.
create or replace function public.create_store_order(
  p_customer_name text,
  p_phone text,
  p_address text,
  p_items jsonb
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_order_id uuid;
  v_item jsonb;
  v_product_id uuid;
  v_quantity integer;
  v_product public.products%rowtype;
  v_total numeric(12,2) := 0;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'Not authorized';
  end if;

  if p_customer_name is null or char_length(btrim(p_customer_name)) not between 2 and 120
     or p_phone is null or char_length(btrim(p_phone)) not between 7 and 25
     or p_address is null or char_length(btrim(p_address)) not between 4 and 500 then
    raise exception 'Invalid customer details';
  end if;

  if jsonb_typeof(p_items) <> 'array'
     or jsonb_array_length(p_items) < 1
     or jsonb_array_length(p_items) > 30 then
    raise exception 'Invalid order items';
  end if;

  insert into public.orders(customer_name, phone, address, total_yer)
  values (btrim(p_customer_name), btrim(p_phone), btrim(p_address), 0)
  returning id into v_order_id;

  for v_item in select value from jsonb_array_elements(p_items)
  loop
    v_product_id := (v_item->>'product_id')::uuid;
    v_quantity := (v_item->>'quantity')::integer;

    if v_quantity is null or v_quantity < 1 or v_quantity > 20 then
      raise exception 'Invalid quantity';
    end if;

    select * into v_product
      from public.products
      where id = v_product_id and is_active = true
      for update;

    if not found then
      raise exception 'Product unavailable';
    end if;

    if v_product.stock < v_quantity then
      raise exception 'Insufficient stock for product %', v_product.name;
    end if;

    update public.products
      set stock = stock - v_quantity, updated_at = now()
      where id = v_product.id;

    insert into public.order_items(
      order_id, product_id, product_name, unit_price_yer, quantity, line_total_yer
    ) values (
      v_order_id, v_product.id, v_product.name, v_product.price_yer,
      v_quantity, v_product.price_yer * v_quantity
    );

    v_total := v_total + (v_product.price_yer * v_quantity);
  end loop;

  update public.orders set total_yer = v_total where id = v_order_id;
  return v_order_id;
end;
$$;

revoke all on function public.create_store_order(text,text,text,jsonb) from public, anon, authenticated;
grant execute on function public.create_store_order(text,text,text,jsonb) to service_role;
