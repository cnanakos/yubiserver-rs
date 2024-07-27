use anyhow::Result;
use parking_lot::{Condvar, Mutex};
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct ObjectPool<T> {
    objects: Mutex<Vec<T>>,
    cond: Condvar,
}

impl<T> ObjectPool<T> {
    pub fn new<F>(cap: usize, init: F) -> Result<ObjectPool<T>>
    where
        F: Fn() -> Result<T>,
    {
        let mut objects = Vec::new();

        for _ in 0..cap {
            objects.push(init()?);
        }

        Ok(ObjectPool {
            objects: Mutex::new(objects),
            cond: Condvar::new(),
        })
    }

    #[inline]
    pub fn get(&self) -> ReusableObject<T> {
        let mut objects = self.objects.lock();
        let mut object = objects.pop();
        while object.is_none() {
            self.cond.wait(&mut objects);
            object = objects.pop();
        }

        let object = object.unwrap();
        ReusableObject::new(self, object)
    }

    #[inline]
    pub fn attach(&self, t: T) {
        let mut objects = self.objects.lock();
        objects.push(t);
        self.cond.notify_one();
    }
}

#[derive(Debug)]
pub struct ReusableObject<'a, T> {
    pool: &'a ObjectPool<T>,
    object: ManuallyDrop<T>,
}

impl<'a, T> ReusableObject<'a, T> {
    pub fn new(pool: &'a ObjectPool<T>, object: T) -> Self {
        Self {
            pool,
            object: ManuallyDrop::new(object),
        }
    }

    #[inline]
    unsafe fn take(&mut self) -> T {
        ManuallyDrop::take(&mut self.object)
    }
}

impl<'a, T> Drop for ReusableObject<'a, T> {
    #[inline]
    fn drop(&mut self) {
        let object = unsafe { self.take() };
        self.pool.attach(object);
    }
}

impl<'a, T> Deref for ReusableObject<'a, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.object
    }
}

impl<'a, T> DerefMut for ReusableObject<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.object
    }
}
