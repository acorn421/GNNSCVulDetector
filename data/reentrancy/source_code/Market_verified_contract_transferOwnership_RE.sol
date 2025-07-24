/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the old owner before updating the owner state variable. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where the external call happens before the state change, enabling the old owner to re-enter the contract while still having owner privileges.
 * 
 * **How the vulnerability can be exploited across multiple transactions:**
 * 
 * 1. **Transaction 1 (Setup)**: The current owner deploys a malicious contract that implements the `onOwnershipTransfer` callback
 * 2. **Transaction 2 (Trigger)**: The owner calls `transferOwnership(newAddress)` which triggers the external call to the old owner's malicious contract
 * 3. **Transaction 3 (Reentrancy)**: During the callback, the malicious contract re-enters and calls sensitive owner-only functions (like `withdrawEther`, `withdrawToken`, or even `transferOwnership` again) while still being the owner
 * 4. **State Exploitation**: The malicious contract can manipulate contract state, drain funds, or transfer ownership to multiple addresses before the original ownership transfer completes
 * 
 * **Why this requires multiple transactions:**
 * 
 * - **State Accumulation**: The vulnerability requires the attacker to first become the owner and then deploy a malicious contract, which requires separate transactions
 * - **Callback Dependency**: The exploit depends on the callback mechanism which only triggers during the ownership transfer process
 * - **Timing Window**: The reentrancy opportunity only exists during the specific window between the external call and the state update, spanning multiple call frames
 * - **Persistent State**: The `owner` state variable maintains its value across transactions, allowing the attacker to retain privileges during the reentrancy window
 * 
 * This vulnerability is realistic because ownership notification callbacks are common in production contracts, and the CEI pattern violation is a subtle but dangerous mistake that has appeared in real-world smart contracts.
 */
pragma solidity ^0.4.0;
contract Ownable {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address oldOwner = owner;
        
        // Notify old owner about ownership transfer - external call before state change
        if (oldOwner != address(0)) {
            oldOwner.call(bytes4(keccak256("onOwnershipTransfer(address)")), newOwner);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = newOwner;
    }
}
contract LockableToken is Ownable {
    function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function approveAndCall(address _spender, uint256 _value, bytes _data) public payable returns (bool);
    function transferAndCall(address _to, uint256 _value, bytes _data) public payable returns (bool);
    function transferFromAndCall(address _from, address _to, uint256 _value, bytes _data) public payable returns (bool);
}

contract Market is Ownable{
    LockableToken private token;
    string public Detail;
    uint256 public SellAmount = 0;
    uint256 public WeiRatio = 0;

    event TokenAddressChange(address token);
    event Buy(address sender,uint256 rate,uint256 value,uint256 amount);

    function () payable public {
        buyTokens(msg.sender);
    }
    
    function tokenDetail(string memory _detail) onlyOwner public {
        Detail = _detail;
    }
    
    function tokenPrice(uint256 _price) onlyOwner public {
        WeiRatio = _price;
    }

    function tokenAddress(address _token) onlyOwner public {
        require(_token != address(0), "Token address cannot be null-address");
        token = LockableToken(_token);
        emit TokenAddressChange(_token);
    }

    function tokenBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function withdrawEther() onlyOwner public  {
        require(address(this).balance > 0, "Not have Ether for withdraw");
        owner.transfer(address(this).balance);
    }
    
    function withdrawToken() onlyOwner public  {
        token.transfer(owner, tokenBalance());
    }

    function buyTokens(address _buyer) private {
        require(_buyer != 0x0);
        require(msg.value > 0);

        uint256 tokens = msg.value * WeiRatio;
        require(tokenBalance() >= tokens, "Not enough tokens for sale");
        token.transfer(_buyer, tokens);
        SellAmount += tokens;

        emit Buy(msg.sender,WeiRatio,msg.value,tokens);
    }
}
