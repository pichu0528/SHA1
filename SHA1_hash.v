module SHA1_hash (       
	clk, 		
	nreset, 	
	start_hash,  
	message_addr,	
	message_size, 	
	hash, 	
	done, 		
	port_A_clk,
        port_A_data_in,
        port_A_data_out,
        port_A_addr,
        port_A_we
	);

input	clk;
input	nreset; 
// Initializes the SHA1_hash module

input	start_hash; 
// Tells SHA1_hash to start hashing the given frame

input [31:0] message_addr; 
// Starting address of the messagetext frame
// i.e., specifies from where SHA1_hash must read the messagetext frame

input [31:0] message_size; 
// Length of the message in bytes

output [159:0] hash; 
// hash results

input [31:0] port_A_data_out; 
// read data from the dpsram (messagetext)

output [31:0] port_A_data_in;
// write data to the dpsram (ciphertext)

output [15:0] port_A_addr;
// address of dpsram being read/written 

output  port_A_clk;
// clock to dpsram (drive this with the input clk) 

output  port_A_we;
// read/write selector for dpsram

output	done; // done is a signal to indicate that hash  is complete

parameter [1:0] State0 = 0, //initializes
					 State1 = 1, //IDEL
			       State2 = 2; //computer and reading or padding 
		
wire [159:0] hash;
wire port_A_clk; 
wire [31:0] S_C;
wire [31:0] NEW_A;
		
reg [31:0] A, B, C, D, E, F, KE, H0, H1, H2, H3, H4; //register to store information with each equal to 32bit
reg [511:0] All_W; //store all 16 values of W
reg [15:0] port_A_addr; //store reading address
reg [1:0] state; //different state
reg [1:0] position; //position of where to padding the 1 
reg [3:0] ct_block; //count for block
reg [7:0] ct_pad; //count for paddding
reg [6:0] ct; //0-80
reg done; // done signal 


assign port_A_we = 0; //since we are just reading, we is always 0
assign hash = {H0,H1,H2,H3,H4}; //assign hash to equal to H0-4 combine
assign port_A_clk = clk;

assign S_C = Shift_n(B, 30); //shifting B by 30 and assign to C
assign NEW_A = Shift_n(A, 5) + All_W[511:480] + F + KE; //calculating NEW A(T)

function [3:0] calc_block; //calculating how many blocks we need 
	input[31:0] message_size;
	begin
		calc_block = (((message_size << 3) + 7'b1000001) >> 9) + 4'b1; //calc_block = total_bits/512 + 1;  	
	end
endfunction

function [31:0] calc_F; //calculating the function F to determine which F to use judging by value of ct
	input [31:0] B, C, D; 
	input [6:0] ct;
	begin
		if (ct < 20)
			calc_F = ((B & C)|((~ B) & D));
		else if (ct < 40)
			calc_F = (B ^ C ^ D);
		else if (ct < 60)
			calc_F = ((B & C)|(B & D)|(C & D));
		else
			calc_F = (B ^ C ^ D);
	end
endfunction

function [7:0] calc_padding; //calculating how many paddings we need 
   input [31:0] message_size; 
	begin 
			calc_padding = (message_size >> 2) + 7'b1; //setting up the padding message by message_size/4 + 1;
	end 
endfunction

function [31:0] Shift_n; //left rotation shift 
	input [31:0] inputT;
	input [4:0] n;
	begin
		Shift_n = ((inputT << n) | (inputT >> 32-n));
	end
endfunction

function [31:0] trans_Endian;   //transform to big-endian   
	input [31:0] value;
	trans_Endian = {value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction
 
function [31:0] calc_K; //calculating which value of K judging by value of ct
	input [6:0] ct;
	begin
		if (ct < 20)
			calc_K = 32'h5a827999;
		else if (ct < 40)
			calc_K = 32'h6ed9eba1;
		else if (ct < 60)
			calc_K = 32'h8f1bbcdc;
		else
			calc_K = 32'hca62c1d6;
	end
endfunction

always @ (posedge clk or negedge nreset)
begin
	if(!nreset)       //reset
		begin      
			state <= State0; 
		end
	
	else	 
		case(state)
			State0: // initializes
			begin
				if(start_hash) 
				begin
					done <= 0;
					ct <= 0;	
					H0 <= 32'h67452301;
					H1 <= 32'hefcdab89;
					H2 <= 32'h98badcfe;
					H3 <= 32'h10325476;
					H4 <= 32'hc3d2e1f0;
					port_A_addr <= message_addr[15:0];
					ct_block <= calc_block(message_size);
					ct_pad <= calc_padding(message_size);
					position <= message_size[1:0];
					state <= State0;
				end 	
				else if (!start_hash)
				begin 
					if (ct_pad != 0)
					begin
						All_W[511:480] <=  trans_Endian(port_A_data_out); //getting data 
						ct_pad <= ct_pad - 7'b1; //reducing padding count
						port_A_addr <= port_A_addr + 16'b100; //move on to next reading element
					end
					else
						All_W[511:480] <= 32'h00000000; // finish padding = 0, means no more data need to read, assign all 0
					ct <= 0;		//reset ct
					state <= State1;
				end 
			end
			
		   State1: //IDLE state 
			begin  
				port_A_addr <= port_A_addr + 16'b100;
				F <= calc_F(H1,H2,H3,ct); 
				KE <= calc_K(ct) + H4;
				A <= H0;
				B <= H1;
				C <= H2;
				D <= H3;
				E <= H4;
				state <= State2;
			end 
			
			State2: //reading&padding and computing state 
			begin 
				if(ct <= 79) // when ct < 80
				begin 
					// computing part begin 
					B <= A;
				   C <= S_C;
				   D <= C;
			      E <= D;
					All_W <= All_W >> 32; //shift All_W by 32 so All_W[511:480] can store new data
				   A <= NEW_A; //S^5(A) + f(t;B,C,D) + E + W(t) + K(t) //calculateing something last clock 
				   F <= calc_F(A,S_C,C,ct+1); //calculting F for next cycle
					KE <= calc_K(ct+1) + D; //calcuting K + E for next cycle
					// computing part end  
					//reading part & padding begin 
					if(ct < 15)// 0 ~ 14 
					begin 
						if(ct_pad >= 1)
						begin
							All_W[511:480] <= trans_Endian(port_A_data_out);
							if(ct < 14) // only need to update reading address when ct is less than 14 for next cycle
								port_A_addr <= port_A_addr + 16'b100;	
							ct_pad <= ct_pad - 7'b1; // reducing padding count when each time read data
							if(ct_pad == 1) // padding 1 for different ending situation, 4 possible situation
							begin 
								if(position == 3)
									All_W[487:480] <= 8'h80;		 
								else if(position == 2)
									All_W[495:480] <= 16'h8000;
								else if(position == 1)
									All_W[503:480] <= 24'h800000;
								else if(position == 0)
									All_W[511:480] <= 32'h80000000;
							end
						end 	
						else if (ct_pad == 0 && ct == 14 && ct_block == 1) //last block and ct == 15 (next cycle) 
							All_W[511:480] <= message_size << 3; //message size * 8		  
					end 
					else
						All_W[511:480] <= Shift_n(((All_W[31:0]^All_W[95:64])^(All_W[287:256]^All_W[447:416])), 1);	//calculting All_W for t > 16
					state <= State2;
					ct <= ct + 7'b1;
				end 	
				else // when ct =  80;
				begin 
					H0 <= A + H0; 
					H1 <= B + H1;
					H2 <= C + H2;
					H3 <= D + H3;
					H4 <= E + H4;
					// setting new H0-4
				   if(ct_block == 1) // last block, done signal applied
						done <= 1;			 
					else
						ct_block <= ct_block - 4'b1; //not last block, reducing ct_block by 1
					state <= State0; //go back to state 0
				end 		
			end 	
		endcase 		
end 
endmodule	