import Image from "next/image";
import toast from "react-hot-toast";

    export default function EditableImage({link, setLink}) {

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
                    <Image className="rounded-lg mb-8 " 
                    src={link} width={250} height={250} alt={'avatar'} />
                )}
                {!link && (
                    <div className="text-center bg-gray-200 p-4 text-gray-500 rounded-lg mb-1">
                        no image
                    </div>
                )}
                {/* <label>
                    <input type="file" className="hidden" onChange={handleFileChange} />
                    <span className="block border border-gray-300 rounded-lg p-2 text-center cursor-pointer">Change image</span>
                </label> */}
            </>
        );
    }