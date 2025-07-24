/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
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
 * 1. **Added State Tracking**: Introduced ownershipTransferAttempts mapping and lastOwnershipTransfer timestamp that persist between transactions
 * 2. **External Call After State Update**: Modified owner state first, then made external call to new owner contract, violating checks-effects-interactions pattern
 * 3. **Reentrancy Vector**: Added onOwnershipTransferred callback that allows malicious owner contracts to re-enter during the ownership transfer process
 * 4. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Deploy malicious contract that implements onOwnershipTransferred
 *    - Transaction 2: Call setOwner with malicious contract address
 *    - During Transaction 2: Malicious contract receives onOwnershipTransferred callback and can re-enter the contract while owner state is already updated but transfer is not finalized
 *    - The persistent state (ownershipTransferAttempts, lastOwnershipTransfer) enables complex multi-call exploitation patterns
 * 
 * The vulnerability exploits the fact that state changes persist between the external call and function completion, allowing reentrancy attacks that depend on the accumulated state from previous transactions.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);
}

contract ROIcrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xc0c026e307B1B74f8d307181Db00CBe2A1B412e0;

    uint256 public price;
    uint256 public tokenSold;

    // Added missing state variables
    mapping(address => uint) public ownershipTransferAttempts;
    uint public lastOwnershipTransfer;

    event FundTransfer(address backer, uint amount, bool isContribution);

    function ROIcrowdsale() public {
        creator = msg.sender;
        price = 26000;
        tokenReward = Token(0x15DE05E084E4C0805d907fcC2Dc5651023c57A48);
    }

    function setOwner(address _owner) public {
        require(msg.sender == creator);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track ownership transfer attempts for audit purposes
        ownershipTransferAttempts[_owner]++;
        
        // Update owner state before external call (vulnerable pattern)
        owner = _owner;
        
        // Notify new owner about ownership transfer (creates reentrancy vector)
        uint256 extcodesize;
        assembly { extcodesize := extcodesize(_owner) }
        if (extcodesize > 0) {
            // External call to contract - potential reentrancy point
            require(_owner.call(bytes4(keccak256("onOwnershipTransferred(address)")), msg.sender), "Owner notification failed");
        }
        
        // Finalize transfer with timestamp (state persists between transactions)
        lastOwnershipTransfer = block.timestamp;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function setCreator(address _creator) public {
        require(msg.sender == creator);
        creator = _creator;      
    }

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        price = _price;      
    }
    
    function kill() public {
        require(msg.sender == creator);
        selfdestruct(owner);
    }
    
    function () payable public {
        require(msg.value > 0);
        require(tokenSold < 138216001);
        uint256 _price = price / 10;
        if(tokenSold < 45136000) {
            _price *= 4;
            _price += price; 
        }
        if(tokenSold > 45135999 && tokenSold < 92456000) {
            _price *= 3;
            _price += price;
        }
        if(tokenSold > 92455999 && tokenSold < 138216000) {
            _price += price; 
        }
        uint amount = msg.value * _price;
        tokenSold += amount / 1 ether;
        tokenReward.transferFrom(owner, msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
