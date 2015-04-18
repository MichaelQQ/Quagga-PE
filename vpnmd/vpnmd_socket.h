
//temp date-plane function
//write data-plane information	
int write_incoming_data_plane(vpn_entry *vpn,unsigned long ip);
int write_outgoing_data_plane(vpn_entry *vpn,unsigned long ip);

//delete data-plane information
int del_incoming_data_plane(int fd,vpn_entry *vpn,unsigned long ip);
int del_outgoing_data_plane(int fd,vpn_entry *vpn,unsigned long ip);
//end temp date-plane function


