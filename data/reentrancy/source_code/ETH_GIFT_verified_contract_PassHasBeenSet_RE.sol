/*
 * ===== SmartInject Injection Details =====
 * Function      : PassHasBeenSet
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Added external call to receiver address before state update, creating a reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability leverages the existing 'reciver' state variable and requires prior setup through SetReciver() function, making it stateful and multi-transaction dependent.
 */
pragma solidity ^0.4.19;

contract ETH_GIFT
{
    function GetGift(bytes pass)
    external
    payable
    {
        if(hashPass == keccak256(pass))
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    function GetGift()
    public
    payable
    {
        if(msg.sender==reciver)
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    bytes32 hashPass;
    
    bool closed = false;
    
    address sender;
    
    address reciver;
 
    function GetHash(bytes pass) public pure returns (bytes32) {return keccak256(pass);}
    
    function SetPass(bytes32 hash)
    public
    payable
    {
        if( (!closed&&(msg.value > 1 ether)) || hashPass==0x00)
        {
            hashPass = hash;
            sender = msg.sender;

        }
    }
   
    function SetReciver(address _reciver)
    public
    {
        if(msg.sender==sender)
        {
            reciver = _reciver;
        }
    }
    
    function PassHasBeenSet(bytes32 hash)
    public
    {
        if(hash==hashPass&&msg.sender==sender)
        {
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           // External call before state update - creates reentrancy window
           if(reciver != address(0)) {
               reciver.call(bytes4(keccak256("onPassConfirmed(address,bytes32)")), msg.sender, hash);
           }
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           closed=true;
        }
    }
    
    function() public payable{}
    
}