export type Question={name:string;type:number;classCode:number};
export function encodeName(name:string){const out:number[]=[];for(const label of name.split('.').filter(Boolean)){const bytes=new TextEncoder().encode(label);out.push(bytes.length,...bytes)}out.push(0);return Uint8Array.from(out)}
export function headerCounts(data:Uint8Array){if(data.length<12)throw new Error('short header');return{questions:(data[4]<<8)|data[5],answers:(data[6]<<8)|data[7]}}
