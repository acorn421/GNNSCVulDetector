/*
 * ===== SmartInject Injection Details =====
 * Function      : setPrice
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a price update notification system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. **Added State Variables**: Added mappings to track pending price updates and confirmations across transactions
 * 2. **Multi-Step Process**: Price updates now require a two-step process: setting pending price and confirming it
 * 3. **External Call Before State Update**: Added external call to `priceOracle.notifyPriceChange()` before state modifications
 * 4. **State Persistence**: Pending updates and confirmations persist between transactions
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls `setPrice()` with malicious price, setting `pendingPriceUpdates[attacker] = maliciousPrice`
 * 2. **Transaction 2**: Attacker calls `confirmPriceUpdate()` to set `priceUpdateConfirmed[attacker] = true`
 * 3. **Transaction 3**: Attacker calls `setPrice()` again - during the external call to `priceOracle.notifyPriceChange()`, the oracle contract can reenter and call `setPrice()` again, exploiting the confirmed state to update the price while the original call is still executing
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the gap between price announcement and confirmation
 * - State must be accumulated across transactions (pending → confirmed → exploited)
 * - The confirmed state from Transaction 2 enables the reentrancy exploitation in Transaction 3
 * - Single transaction cannot achieve this as the confirmation state needs to be set beforehand
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world oracle notification systems where price changes need external validation, making it a believable production vulnerability.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) external;
}

// Added interface for Price Oracle to fix undeclared identifier
interface IPriceOracle {
    function notifyPriceChange(uint256 _price, address _sender) external;
}

contract CFNDCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x56D215183E48881f10D1FaEb9325cf02171B16B7;

    uint256 private price;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    // Changed deprecated constructor syntax to 'constructor'
    constructor() public {
        creator = msg.sender;
        price = 400;
        tokenReward = Token(0x2a7d19F2bfd99F46322B03C2d3FdC7B7756cAe1a);
    }

    function setOwner(address _owner) isCreator public {
        owner = _owner;      
    }

    function setCreator(address _creator) isCreator public {
        creator = _creator;      
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public pendingPriceUpdates;
    mapping(address => bool) public priceUpdateConfirmed;
    uint256 public priceUpdateCount;
    address public priceOracle;
    
    function setPrice(uint256 _price) isCreator public {
        // Store pending price update for multi-step process
        pendingPriceUpdates[msg.sender] = _price;
        priceUpdateCount++;
        
        // Notify external price oracle before updating state
        if (priceOracle != address(0)) {
            // External call before state update - vulnerable to reentrancy
            IPriceOracle(priceOracle).notifyPriceChange(_price, msg.sender);
        }
        
        // Only update price if this is a confirmed update (requires prior pending state)
        if (priceUpdateConfirmed[msg.sender]) {
            price = pendingPriceUpdates[msg.sender];
            priceUpdateConfirmed[msg.sender] = false;
            pendingPriceUpdates[msg.sender] = 0;
        }
    }
    
    function confirmPriceUpdate() isCreator public {
        require(pendingPriceUpdates[msg.sender] > 0, "No pending price update");
        priceUpdateConfirmed[msg.sender] = true;
    }
    
    function setPriceOracle(address _oracle) isCreator public {
        priceOracle = _oracle;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function sendToken(address _to, uint256 _value) isCreator public {
        tokenReward.transfer(_to, _value);      
    }

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > 1527238800);
        uint256 amount = msg.value * price;
        uint256 _amount = amount / 100;

        
        // stage 1
        if (now > 1527238800 && now < 1527670800) {
            amount += _amount * 15;
        }

        // stage 2
        if (now > 1527843600 && now < 1528189200) {
            amount += _amount * 10;
        }

        // stage 3
        if (now > 1528275600 && now < 1528621200) {
            amount += _amount * 5;
        }

        // stage 4
        if (now > 1528707600 && now < 1529053200) {
            amount += _amount * 2;
        }

        // stage 5
        require(now < 1531123200);

        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
