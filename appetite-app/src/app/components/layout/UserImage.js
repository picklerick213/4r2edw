import Image from "next/image";
import toast from "react-hot-toast";

    export default function UserImage({link, setLink}) {

        async function handleFileChange(ev) {
            const files = ev.target.files;
            if (files?.length === 1) {
                const data = new FormData;
                data.set('file', files[0]);

            const uploadPromise = fetch('./api/upload', {
                method: 'POST',
                body: data,
            }).then(response => {
                if (response.ok) {
                    return response.json().then(json => {
                        setLink(link);
                    })
                }
                throw new Error('Something went wrong');
            });        
            await toast.promise(uploadPromise, {
                loading: 'Uploading...',
                success: 'Uploading Success',
                error: 'Uploading Error',
            });
            }
        }
        return (
            <>
                {link && (
                    <Image className="rounded-lg mb-1" 
                    src={link} width={20} height={20} alt={'avatar'} />
                )}
            </>
        );
    }