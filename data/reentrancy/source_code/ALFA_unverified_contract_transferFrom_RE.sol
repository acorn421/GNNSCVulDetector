/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `pendingRedemptions` mapping to track pending redemption amounts and `redemptionAttempts` to count redemption attempts per user.
 * 
 * 2. **Reordered Operations**: For users with multiple redemption attempts, the external call `_from.transfer(pendingAmount)` now happens BEFORE critical state updates (balanceOf reduction, Bank adjustment, totalSupply changes).
 * 
 * 3. **Multi-Transaction Logic**: The vulnerability only activates after the first redemption attempt (`redemptionAttempts[_from] > 1`), requiring multiple transactions to exploit.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - User calls transferFrom() to redeem tokens for the first time
 * - `redemptionAttempts[_from] = 1`
 * - Normal execution path: state updates happen, then transfer occurs
 * - User receives expected ETH amount
 * 
 * **Transaction 2+ (Exploitation):**
 * - User calls transferFrom() again with a malicious contract as `_from`
 * - `redemptionAttempts[_from] > 1` condition is met
 * - Pending redemption amount is added to `pendingRedemptions[_from]`
 * - **VULNERABILITY**: External call `_from.transfer(pendingAmount)` happens BEFORE state updates
 * - During the transfer, the malicious contract can re-enter transferFrom()
 * - On re-entry, the balanceOf[_from] hasn't been reduced yet, allowing multiple withdrawals
 * - The price calculation uses stale values since Bank and totalSupply haven't been updated
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on `redemptionAttempts[_from]` being greater than 1, which can only happen across multiple transactions.
 * 
 * 2. **Pending Redemption Building**: The `pendingRedemptions` mapping accumulates values across transactions, creating larger amounts available for exploitation.
 * 
 * 3. **Price Manipulation**: Multiple transactions allow the attacker to manipulate the price calculation by exploiting the timing between external calls and state updates.
 * 
 * 4. **Trust Building**: The first transaction establishes the user as a legitimate redeemer, making subsequent malicious transactions less suspicious.
 * 
 * This creates a realistic vulnerability where an attacker must first establish a transaction history before being able to exploit the reentrancy flaw, making it stateful and multi-transaction dependent.
 */
pragma solidity ^0.4.25;

/*     ONUP TOKEN AFFILIATE PROJECT, THE FIRST EDITION
        CREATED 2018-10-31 BY DAO DRIVER ETHEREUM
        ALL PROJECT DETAILS AT https://onup.online       */

library SafeMath {
    function mul(uint256 a, uint256 b)internal pure returns(uint256){if(a==0){return 0;}uint256 c=a*b;assert(c/a==b);return c;}
    function div(uint256 a, uint256 b)internal pure returns(uint256){uint256 c=a/b;return c;}
    function sub(uint256 a, uint256 b)internal pure returns(uint256){assert(b<=a);return a-b;}
    function add(uint256 a, uint256 b)internal pure returns(uint256){uint256 c=a+b;assert(c>=a);return c;}
}
contract ERC20 {uint256 internal Bank=0;string public constant name="OnUp TOKEN";string public constant symbol="OnUp";
    uint8  public constant decimals=6; uint256 public price=700000000; uint256 public totalSupply;
    event Approval(address indexed owner,address indexed spender,uint value);
    event Transfer(address indexed from,address indexed to,uint value);
    mapping(address=>mapping(address=>uint256))public allowance; mapping(address=>uint256)public balanceOf;
    function balanceOf(address who)public constant returns(uint){return balanceOf[who];}
    function approve(address _spender,uint _value)public{allowance[msg.sender][_spender]=_value; emit Approval(msg.sender,_spender,_value);}
    function allowance(address _owner,address _spender) public constant returns (uint remaining){return allowance[_owner][_spender];} 
}
contract ALFA is ERC20{using SafeMath for uint256;
    modifier onlyPayloadSize(uint size){require(msg.data.length >= size + 4); _;}
    address  ref1 = 0x0000000000000000000000000000000000000000;
    address  ref2 = 0x0000000000000000000000000000000000000000;
    address  ref3 = 0x0000000000000000000000000000000000000000;
    address  ref4 = 0x0000000000000000000000000000000000000000;
    address  ref5 = 0x0000000000000000000000000000000000000000;
    address public owner;
    address internal constant insdr = 0xaB85Cb1087ce716E11dC37c69EaaBc09d674575d;// FEEDER 
    address internal constant advrt = 0x28fF20D2d413A346F123198385CCf16E15295351;// ADVERTISE
    address internal constant spcnv = 0x516e0deBB3dB8C2c087786CcF7653fa0991784b3;// AIRDROPS
    mapping (address => address) public referrerOf;
    mapping (address => uint256) public prevOf;
    mapping (address => uint256) public summOf;
    constructor()public payable{owner=msg.sender;prevOf[advrt]=6;prevOf[owner]=6;}
    function()payable public{
        require(msg.value >= 10000000000000000);
        require(msg.value <= 30000000000000000000);
        require(isContract(msg.sender)==false); 
        if( msg.sender!=insdr ){
            ref1=0x0000000000000000000000000000000000000000; 
            ref2=0x0000000000000000000000000000000000000000;
            ref3=0x0000000000000000000000000000000000000000;
            ref4=0x0000000000000000000000000000000000000000;
            ref5=0x0000000000000000000000000000000000000000;
            if(msg.sender!= advrt && msg.sender!=owner){CheckPrivilege();}else{mintTokens();}
        }else{Bank+=(msg.value.div(100)).mul(90);price=Bank.div(totalSupply);}
    }
    function CheckPrivilege()internal{
        if(msg.value>=25000000000000000000 && prevOf[msg.sender]<6){prevOf[msg.sender]=6;}
        if(msg.value>=20000000000000000000 && prevOf[msg.sender]<5){prevOf[msg.sender]=5;}
        if(msg.value>=15000000000000000000 && prevOf[msg.sender]<4){prevOf[msg.sender]=4;}
        if(msg.value>=10000000000000000000 && prevOf[msg.sender]<3){prevOf[msg.sender]=3;}
        if(msg.value>= 5000000000000000000 && prevOf[msg.sender]<2){prevOf[msg.sender]=2;} 
        if(msg.value>=  100000000000000000 && prevOf[msg.sender]<1){prevOf[msg.sender]=1;}
        if(summOf[msg.sender]>=250000000000000000000 && prevOf[msg.sender]<6){prevOf[msg.sender]=6;}
		if(summOf[msg.sender]>=200000000000000000000 && prevOf[msg.sender]<5){prevOf[msg.sender]=5;}
		if(summOf[msg.sender]>=150000000000000000000 && prevOf[msg.sender]<4){prevOf[msg.sender]=4;}
		if(summOf[msg.sender]>=100000000000000000000 && prevOf[msg.sender]<3){prevOf[msg.sender]=3;}
		if(summOf[msg.sender]>= 50000000000000000000 && prevOf[msg.sender]<2){prevOf[msg.sender]=2;}
		ref1=referrerOf[msg.sender];if(ref1==0x0000000000000000000000000000000000000000){
		ref1=bytesToAddress(msg.data);require(isContract(ref1)==false);require(balanceOf[ref1]>0);require(ref1!=spcnv);
		require(ref1!=insdr);referrerOf[msg.sender]=ref1;}mintTokens();
    }
    function mintTokens()internal{
        uint256 tokens=msg.value.div((price*100).div(70));
        require(tokens>0);require(balanceOf[msg.sender]+tokens>balanceOf[msg.sender]);
        uint256 perc=msg.value.div(100);uint256 sif=perc.mul(10);
        uint256 percair=0;uint256 bonus1=0;uint256 bonus2=0;uint256 bonus3=0;
        uint256 bonus4=0;uint256 bonus5=0;uint256 minus=0;uint256 airdrop=0;
        if(msg.sender!=advrt && msg.sender!=owner && msg.sender!=spcnv){
        if(ref1!=0x0000000000000000000000000000000000000000){summOf[ref1]+=msg.value; 
        if(prevOf[ref1]>1){sif-=perc.mul(2);bonus1=perc.mul(2);minus+=2;} 
        else if(prevOf[ref1]>0){sif-=perc;bonus1=perc;minus+=1;}else{}
        if(ref2!= 0x0000000000000000000000000000000000000000){ 
        if(prevOf[ref2]>2){sif-=perc.mul(2);bonus2=perc.mul(2);minus+=2;}
        else if(prevOf[ref2]>0){sif-=perc;bonus2=perc;minus+=1;}else{}
        if(ref3!= 0x0000000000000000000000000000000000000000){ 
        if(prevOf[ref3]>3){sif-=perc.mul(2);bonus3=perc.mul(2);minus+=2;}
        else if(prevOf[ref3]>0){sif-=perc;bonus3=perc;minus+=1;}else{}
        if(ref4!= 0x0000000000000000000000000000000000000000){ 
        if(prevOf[ref4]>4){sif-=perc.mul(2);bonus4=perc.mul(2);minus+=2;}
        else if(prevOf[ref4]>0){sif-=perc;bonus4=perc;minus+=1;}else{}
        if(ref5!= 0x0000000000000000000000000000000000000000){ 
        if(prevOf[ref5]>5){sif-=perc.mul(2);bonus5=perc.mul(2);minus+= 2;}
        else if(prevOf[ref5]>0){sif-=perc;bonus5=perc;minus+=1;}else{}}}}}}} 
        if(sif>0){
            airdrop=sif.div((price*100).div(70)); 
            require(airdrop>0); 
            percair=sif.div(100);
            balanceOf[spcnv]+=airdrop; 
            emit Transfer(this,spcnv,airdrop);}
        Bank+=(perc+percair).mul(85-minus);    
        totalSupply+=(tokens+airdrop);
        price=Bank.div(totalSupply);
        balanceOf[msg.sender]+=tokens;
        emit Transfer(this,msg.sender,tokens);
        tokens=0;airdrop=0;
        owner.transfer(perc.mul(5)); 
        advrt.transfer(perc.mul(5));
        if(bonus1>0){ref1.transfer(bonus1);} 
        if(bonus2>0){ref2.transfer(bonus2);} 
        if(bonus3>0){ref3.transfer(bonus3);} 
        if(bonus4>0){ref4.transfer(bonus4);} 
        if(bonus5>0){ref5.transfer(bonus5);}
    }
      function transfer(address _to,uint _value)
      public onlyPayloadSize(2*32)returns(bool success){
        require(balanceOf[msg.sender]>=_value);
        if(_to!=address(this)){
            if(msg.sender==spcnv){require(_value<10000001);}
            require(balanceOf[_to]+_value>=balanceOf[_to]);
            balanceOf[msg.sender] -=_value;
            balanceOf[_to]+=_value;
            emit Transfer(msg.sender,_to,_value);
        }else{require(msg.sender!=spcnv);
        balanceOf[msg.sender]-=_value;uint256 change=_value.mul(price);
        require(address(this).balance>=change);
        if(totalSupply>_value){
            uint256 plus=(address(this).balance-Bank).div(totalSupply);
            Bank-=change;totalSupply-=_value;Bank+=(plus.mul(_value));
            price=Bank.div(totalSupply);
            emit Transfer(msg.sender,_to,_value);}
        if(totalSupply==_value){
            price=address(this).balance.div(totalSupply);
            price=(price.mul(101)).div(100);totalSupply=0;Bank=0;
            emit Transfer(msg.sender,_to,_value);
            owner.transfer(address(this).balance-change);}
        msg.sender.transfer(change);}return true;
      }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) private pendingRedemptions;
mapping(address => uint256) private redemptionAttempts;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function transferFrom(address _from,address _to,uint _value)
    public onlyPayloadSize(3*32)returns(bool success){
        require(balanceOf[_from]>=_value);require(allowance[_from][msg.sender]>=_value);
        if(_to!=address(this)){
            if(msg.sender==spcnv){require(_value<10000001);}
            require(balanceOf[_to]+_value>=balanceOf[_to]);
            balanceOf[_from]-=_value;balanceOf[_to]+=_value;
            allowance[_from][msg.sender]-=_value;
            emit Transfer(_from,_to,_value);
        }else{require(_from!=spcnv);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track redemption attempts for multi-transaction exploitation
        redemptionAttempts[_from]++;
        
        // Calculate change amount using potentially stale price
        uint256 change=_value.mul(price);
        require(address(this).balance>=change);
        
        // Add to pending redemptions before state updates
        pendingRedemptions[_from] += change;
        
        // Early external call before critical state updates - VULNERABILITY!
        if(redemptionAttempts[_from] > 1 && pendingRedemptions[_from] > 0){
            // Remove pending after successful transfer
            uint256 pendingAmount = pendingRedemptions[_from];
            pendingRedemptions[_from] = 0;
            _from.transfer(pendingAmount); // VULNERABLE: External call before state updates
        }
        
        // Critical state updates happen AFTER external call
        balanceOf[_from]-=_value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if(totalSupply>_value){
            uint256 plus=(address(this).balance-Bank).div(totalSupply);
            Bank-=change;
            totalSupply-=_value;
            Bank+=(plus.mul(_value));
            price=Bank.div(totalSupply);
            emit Transfer(_from,_to,_value);
            allowance[_from][msg.sender]-=_value;} 
        if(totalSupply==_value){
            price=address(this).balance.div(totalSupply);
            price=(price.mul(101)).div(100);totalSupply=0;Bank=0;
            emit Transfer(_from,_to,_value);allowance[_from][msg.sender]-=_value;
            owner.transfer(address(this).balance - change);}
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Regular transfer for first-time redemptions
        if(redemptionAttempts[_from] == 1){
            _from.transfer(change);
        }
        }return true;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    function bytesToAddress(bytes source)internal pure returns(address addr){assembly{addr:=mload(add(source,0x14))}return addr;}
    function isContract(address addr)internal view returns(bool){uint size;assembly{size:=extcodesize(addr)}return size>0;}
}