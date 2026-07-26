package utils;

import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 线程安全的有界集合。容量满时移除最早写入的元素，适合保存长期运行任务的去重键。
 */
public class BoundedSet<E> extends AbstractSet<E> {
    private final int maximumSize;
    private final LinkedHashMap<E, Boolean> entries = new LinkedHashMap<E, Boolean>();

    /** 创建指定正容量的集合。 */
    public BoundedSet(int maximumSize) {
        if (maximumSize <= 0) {
            throw new IllegalArgumentException("Maximum size must be positive");
        }
        this.maximumSize = maximumSize;
    }

    /** 添加新元素，并在超出容量时淘汰最早写入的元素。 */
    @Override
    public synchronized boolean add(E element) {
        if (entries.containsKey(element)) {
            return false;
        }
        entries.put(element, Boolean.TRUE);
        if (entries.size() > maximumSize) {
            Iterator<Map.Entry<E, Boolean>> iterator = entries.entrySet().iterator();
            iterator.next();
            iterator.remove();
        }
        return true;
    }

    /** 返回快照迭代器，避免调用方在迭代期间持有内部锁。 */
    @Override
    public synchronized Iterator<E> iterator() {
        Iterator<E> snapshot = new ArrayList<E>(entries.keySet()).iterator();
        return new Iterator<E>() {
            private E current;
            private boolean removable;

            /** 判断快照中是否还有元素。 */
            @Override
            public boolean hasNext() {
                return snapshot.hasNext();
            }

            /** 返回快照中的下一个元素，并允许删除该元素。 */
            @Override
            public E next() {
                current = snapshot.next();
                removable = true;
                return current;
            }

            /** 删除快照当前元素时同步删除底层集合，保持 Set 迭代器契约。 */
            @Override
            public void remove() {
                if (!removable) {
                    throw new IllegalStateException("next() must be called before remove()");
                }
                BoundedSet.this.remove(current);
                removable = false;
            }
        };
    }

    /** 返回当前保存的元素数量。 */
    @Override
    public synchronized int size() {
        return entries.size();
    }

    /** 判断元素是否仍在当前去重窗口内。 */
    @Override
    public synchronized boolean contains(Object element) {
        return entries.containsKey(element);
    }

    /** 删除指定去重键。 */
    @Override
    public synchronized boolean remove(Object element) {
        return entries.remove(element) != null;
    }

    /** 清空所有去重键。 */
    @Override
    public synchronized void clear() {
        entries.clear();
    }
}
