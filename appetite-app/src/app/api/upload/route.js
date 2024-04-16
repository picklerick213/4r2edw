export async function POST(req) {
    const data = await req.formData();
    if (data.get('file')){
        ///upload file 
      const file = data.get('data');  
    }
    return Response.json(true);
}