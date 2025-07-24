/*
 * ===== SmartInject Injection Details =====
 * Function      : setPrice
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
 * 1. **Added State Variables**: 
 *    - `pendingPriceUpdates` mapping to track pending price changes
 *    - `priceChangeNonces` mapping to track update sequences per address
 *    - `priceOracle` address for external notifications
 * 
 * 2. **Created Multi-Transaction Dependency**:
 *    - Each price update gets a unique nonce that must be processed sequentially
 *    - The pending state persists between transactions
 *    - Multiple calls are needed to accumulate nonces and manipulate state
 * 
 * 3. **Introduced Reentrancy Point**:
 *    - External call to `priceOracle.notifyPriceChange()` before state finalization
 *    - Uses low-level `call()` which can trigger reentrancy
 *    - State updates happen after the external call, violating CEI pattern
 * 
 * 4. **Multi-Transaction Exploitation**:
 *    - Transaction 1: Attacker calls `setPrice()` to set pending state and increment nonce
 *    - Transaction 2: During oracle notification, attacker reenters to manipulate `pendingPriceUpdates`
 *    - Transaction 3: Original call completes with manipulated state
 *    - Multiple transactions needed to build up nonces and exploit the race condition
 * 
 * 5. **Realistic Integration**:
 *    - Price oracle notifications are common in DeFi
 *    - Nonce-based updates are realistic for preventing replay attacks
 *    - The pending update pattern mirrors real-world multi-step processes
 * 
 * The vulnerability requires multiple transactions because the nonce increments and pending state must be built up over time, and the reentrancy can only be exploited during the specific window when the oracle call is made.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) external;
}

contract TBECrowdsale {
    
    Token public tokenReward;
    uint256 public price;
    address public creator;
    address public owner = 0x0;
    uint256 public startDate;
    uint256 public endDate;

    mapping (address => bool) public whitelist;
    mapping (address => bool) public categorie1;
    mapping (address => bool) public categorie2;
    mapping (address => uint256) public balanceOfEther;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function TBECrowdsale() public {
        creator = msg.sender;
        price = 8000;
        startDate = now;
        endDate = startDate + 30 days;
        tokenReward = Token(0x647972c6A5bD977Db85dC364d18cC05D3Db70378);
    }

    function setOwner(address _owner) isCreator public {
        owner = _owner;      
    }

    function setCreator(address _creator) isCreator public {
        creator = _creator;      
    }

    function setStartDate(uint256 _startDate) isCreator public {
        startDate = _startDate;      
    }

    function setEndtDate(uint256 _endDate) isCreator public {
        endDate = _endDate;      
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (uint256 => bool) public pendingPriceUpdates;
    mapping (address => uint256) public priceChangeNonces;
    address public priceOracle;
    
    function setPrice(uint256 _price) isCreator public {
        uint256 nonce = priceChangeNonces[msg.sender];
        pendingPriceUpdates[nonce] = true;
        priceChangeNonces[msg.sender]++;
        
        // External call to oracle before state update - reentrancy point
        if (address(priceOracle) != 0) {
            (bool success, ) = priceOracle.call(abi.encodeWithSignature("notifyPriceChange(uint256,uint256)", _price, nonce));
            require(success, "Oracle notification failed");
        }
        
        // State update after external call - violates CEI pattern
        if (pendingPriceUpdates[nonce]) {
            price = _price;
            delete pendingPriceUpdates[nonce];
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function addToWhitelist(address _address) isCreator public {
        whitelist[_address] = true;
    }

    function addToCategorie1(address _address) isCreator public {
        categorie1[_address] = true;
    }

    function addToCategorie2(address _address) isCreator public {
        categorie2[_address] = true;
    }

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
        require(now > startDate);
        require(now < endDate);
        require(whitelist[msg.sender]);
        
        if (categorie1[msg.sender]) {
            require(balanceOfEther[msg.sender] <= 2);
        }

        uint256 amount = msg.value * price;

        if (now > startDate && now <= startDate + 5) {
            uint256 _amount = amount / 10;
            amount += _amount * 3;
        }

        balanceOfEther[msg.sender] += msg.value / 1 ether;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}