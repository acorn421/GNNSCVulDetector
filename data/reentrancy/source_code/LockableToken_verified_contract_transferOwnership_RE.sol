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
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the newOwner address before updating the owner state. This violates the Checks-Effects-Interactions pattern and enables a multi-transaction attack where:
 * 
 * 1. **Transaction 1**: Attacker calls transferOwnership with a malicious contract address
 * 2. **During external call**: The malicious contract can re-enter transferOwnership while the original owner state is still unchanged
 * 3. **Transaction 2 (reentrant)**: The malicious contract can call transferOwnership again with a different address, bypassing the onlyOwner check since the owner hasn't been updated yet
 * 4. **State persistence**: The vulnerability exploits the fact that owner state persists between transactions and can be manipulated through carefully timed reentrant calls
 * 
 * The vulnerability requires multiple transactions because:
 * - The initial call must set up the external call context
 * - The reentrant call must occur during the external call execution
 * - The exploit depends on the owner state not being updated between the initial call and the reentrant call
 * - Multiple ownership transfers can be chained through accumulated state manipulation
 * 
 * This creates a realistic scenario where ownership can be transferred to unintended addresses through reentrancy, potentially allowing an attacker to gain control over critical contract functions that depend on the owner state.
 */
pragma solidity ^0.4.0;
contract Ownable {
    address public owner;

    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify new owner about pending ownership transfer
        if (newOwner != address(0)) {
            // Best effort notification via low-level call
            if (newOwner.call(bytes4(keccak256("onOwnershipTransfer(address)")), owner)) {
                // Notification succeeded
            } else {
                require(false, "Ownership transfer notification failed");
            }
        }
        // Update owner state after external call - violates CEI pattern
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
    
    function tokenDetail(string _detail) onlyOwner public {
        Detail = _detail;
    }
    
    function tokenPrice(uint256 _price) onlyOwner public {
        WeiRatio = _price;
    }

    function tokenAddress(address _token) onlyOwner public {
        require(_token != address(0));
        token = LockableToken(_token);
        emit TokenAddressChange(_token);
    }

    function tokenBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function withdrawEther() onlyOwner public  {
        require(this.balance > 0);
        owner.transfer(this.balance);
    }
    
    function withdrawToken() onlyOwner public  {
        token.transfer(owner, tokenBalance());
    }

    function buyTokens(address _buyer) private {
        require(_buyer != 0x0);
        require(msg.value > 0);

        uint256 tokens = msg.value * WeiRatio;
        require(tokenBalance() >= tokens);
        token.transfer(_buyer, tokens);
        SellAmount += tokens;

        emit Buy(msg.sender,WeiRatio,msg.value,tokens);
    }
}