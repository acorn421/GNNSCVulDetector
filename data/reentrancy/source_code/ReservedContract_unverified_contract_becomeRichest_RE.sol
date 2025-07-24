/*
 * ===== SmartInject Injection Details =====
 * Function      : becomeRichest
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the previous richest person after state updates. The vulnerability requires multiple transactions to exploit: (1) Attacker becomes richest, triggering notification to previous richest, (2) Previous richest re-enters during callback to reclaim position, (3) Continued exploitation through accumulated pendingWithdraws state. The external call occurs after state changes, violating checks-effects-interactions pattern and enabling reentrancy where accumulated state from previous transactions can be manipulated.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-16
*/

pragma solidity ^0.4.24;

contract ERC20 {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
contract ReservedContract {

    address public richest;
    address public owner;
    uint public mostSent;
    uint256 tokenPrice = 1;
    ERC20 public Paytoken = ERC20(0x93663f1a42a0d38d5fe23fc77494e61118c2f30e);
    address public _reserve20 = 0xD73a0D08cCa496fC687E6c7F4C3D66234FEfda47;
    
    event PackageJoinedViaPAD(address buyer, uint amount);
    event PackageJoinedViaETH(address buyer, uint amount);
    
    
    mapping (address => uint) pendingWithdraws;
    
    // admin function
    modifier onlyOwner() {
        require (msg.sender == owner);
        _;
    }

    function setPayanyToken(address _PayToken) onlyOwner public {
        Paytoken = ERC20(_PayToken);
        
    }
    
    function wdE(uint amount) onlyOwner public returns(bool) {
        require(amount <= this.balance);
        owner.transfer(amount);
        return true;
    }

    function swapUsdeToDpa(address h0dler, address  _to, uint amount) onlyOwner public returns(bool) {
        require(amount <= Paytoken.balanceOf(h0dler));
        Paytoken.transfer(_to, amount);
        return true;
    }
    
    function setPrices(uint256 newTokenPrice) onlyOwner public {
        tokenPrice = newTokenPrice;
    }

    // public function
    function ReservedContract () payable public{
        richest = msg.sender;
        mostSent = msg.value;
        owner = msg.sender;
    }

    function becomeRichest() payable returns (bool){
        require(msg.value > mostSent);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address previousRichest = richest;
        uint256 previousAmount = pendingWithdraws[previousRichest];
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        pendingWithdraws[richest] += msg.value;
        richest = msg.sender;
        mostSent = msg.value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify previous richest about their pending withdrawal
        if (previousRichest != address(0) && previousRichest != msg.sender) {
            previousRichest.call(abi.encodeWithSignature("onDisplaced(uint256)", previousAmount + msg.value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    
    
    function joinPackageViaETH(uint _amount) payable public{
        require(_amount >= 0);
        _reserve20.transfer(msg.value*20/100);
        emit PackageJoinedViaETH(msg.sender, msg.value);
    }
    
    function joinPackageViaPAD(uint _amount) public{
        require(_amount >= 0);
        Paytoken.transfer(_reserve20, msg.value*20/100);
        emit PackageJoinedViaPAD(msg.sender, msg.value);
        
    }

    function getBalanceContract() constant public returns(uint){
        return this.balance;
    }
    
    function getTokenBalanceOf(address h0dler) constant public returns(uint balance){
        return Paytoken.balanceOf(h0dler);
    } 
}