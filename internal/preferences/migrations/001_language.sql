CREATE TABLE uem_user_preferences (
 user_id TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
 locale TEXT NOT NULL CHECK (locale IN ('','en','ca','fr','de','no','pt','es'))
);
