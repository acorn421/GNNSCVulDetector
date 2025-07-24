/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created `approvalActive`, `pendingApprovals` mappings to track approval state across transactions
 * 2. **External Call Before State Update**: Added external call to spender contract before updating allowance state
 * 3. **Vulnerable State Management**: State updates occur after external call, allowing reentrancy manipulation
 * 4. **Multi-Transaction Dependency**: The vulnerability requires multiple function calls to build up exploitable state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: User calls approve() → sets approvalActive[user] = true → external call to malicious spender
 * - **Transaction 2**: Malicious spender can call approve() again during callback, manipulating the approvalActive state
 * - **Transaction 3**: Original approval completes with corrupted state, allowing double-spending or allowance manipulation
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the persistent state in `approvalActive` mapping
 * - Requires sequence of approve calls to create conflicting state
 * - Cannot be exploited in single transaction due to state dependencies
 * - Accumulated state changes across multiple calls enable the exploit
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(bytes32 => uint) public allowanceMapping;
    mapping(address => bool) public approvalActive;
    mapping(address => address) public pendingApprovals;

    function approve(address spender, uint tokens) public returns (bool success) {
        // Store pending approval state before external call
        pendingApprovals[msg.sender] = spender;
        approvalActive[msg.sender] = true;
        
        // External call to spender for approval notification - VULNERABILITY POINT
        uint length;
        assembly { length := extcodesize(spender) }
        if (length > 0) {
            // low-level call as per modified code (ignore result)
            spender.call(
                abi.encodeWithSignature("onApprovalReceived(address,uint256)", msg.sender, tokens)
            );
        }
        
        // State update happens AFTER external call - REENTRANCY VULNERABILITY
        if (approvalActive[msg.sender]) {
            allowanceMapping[keccak256(abi.encodePacked(msg.sender, spender))] = tokens;
            approvalActive[msg.sender] = false;
            pendingApprovals[msg.sender] = address(0);
            
            emit Approval(msg.sender, spender, tokens);
            return true;
        }
        
        return false;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
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
        require(amount <= address(this).balance);
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
    constructor() public payable {
        richest = msg.sender;
        mostSent = msg.value;
        owner = msg.sender;
    }

    function becomeRichest() public payable returns (bool){
        require(msg.value > mostSent);
        pendingWithdraws[richest] += msg.value;
        richest = msg.sender;
        mostSent = msg.value;
        return true;
    }
    
    
    function joinPackageViaETH(uint _amount) public payable {
        require(_amount >= 0);
        _reserve20.transfer(msg.value*20/100);
        emit PackageJoinedViaETH(msg.sender, msg.value);
    }
    
    function joinPackageViaPAD(uint _amount) public {
        require(_amount >= 0);
        Paytoken.transfer(_reserve20, msg.value*20/100);
        emit PackageJoinedViaPAD(msg.sender, msg.value);
        
    }

    function getBalanceContract() public constant returns(uint){
        return address(this).balance;
    }
    
    function getTokenBalanceOf(address h0dler) public constant returns(uint balance){
        return Paytoken.balanceOf(h0dler);
    } 
}
