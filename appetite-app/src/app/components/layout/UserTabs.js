'use client';
import Link from "next/link";
import { usePathname } from "next/navigation";

export default function UserTabs({isAdmin}){
    const path = usePathname();
    return(
        <div className="column-container text-xs gap-4 tabs justify-center items-center py-4">
            <Link className={path === '/profile' ? 'active' : ''} href={'/profile'}>Profile</Link>
                {isAdmin &&(
                    <>
                    <Link 
                        className={path === '/categories' ? 'active' : ''} 
                        href={'/categories'}>
                            Categories
                    </Link>
                    <Link 
                        className={path.includes('menu-items') ? 'active' : ''} 
                        href={'/menu-items'}>
                            Menu Items
                    </Link>
                    <Link 
                    className={path.includes('/users') ? 'active' : ''} 
                    href={'/users'}>
                        Users
                    </Link>
                    </>
                )}
        </div>
    );
}