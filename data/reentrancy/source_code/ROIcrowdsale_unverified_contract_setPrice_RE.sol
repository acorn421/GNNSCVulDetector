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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a price update notification system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1: Setup Phase**
 * - Attacker deploys malicious contract and calls subscribeToUpdates() to register as a price update subscriber
 * - This establishes the necessary state for the attack
 * 
 * **Transaction 2: Exploitation Phase**
 * - Creator calls setPrice() with new price
 * - Function sets pendingPrice and priceUpdateInProgress = true
 * - External call made to attacker's contract via onPriceUpdate callback
 * - During callback, attacker can re-enter the crowdsale contract through fallback function
 * - The fallback function still uses the old price value since price hasn't been updated yet
 * - Attacker can purchase tokens at old price while knowing the new (higher) price is coming
 * - After callback returns, price is finally updated to new value
 * 
 * **Key Vulnerability Elements:**
 * 1. **State Persistence**: Subscriber registration persists between transactions
 * 2. **Multi-Transaction Requirement**: Cannot exploit without first registering as subscriber
 * 3. **Timing Window**: External call happens before state update, creating reentrancy opportunity
 * 4. **Information Asymmetry**: Attacker knows future price during callback but transactions use old price
 * 
 * **Exploitation Sequence:**
 * 1. Deploy malicious contract implementing onPriceUpdate
 * 2. Call subscribeToUpdates() to register
 * 3. Wait for creator to call setPrice() with higher price
 * 4. During callback, purchase tokens at old price via fallback function
 * 5. Profit from price arbitrage opportunity
 * 
 * The vulnerability is realistic as price update notifications are common in DeFi protocols, and the timing-based nature makes it a genuine multi-transaction attack vector.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

contract ROIcrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xc0c026e307B1B74f8d307181Db00CBe2A1B412e0;

    uint256 public price;
    uint256 public tokenSold;

    event FundTransfer(address backer, uint amount, bool isContribution);

    function ROIcrowdsale() public {
        creator = msg.sender;
        price = 26000;
        tokenReward = Token(0x15DE05E084E4C0805d907fcC2Dc5651023c57A48);
    }

    function setOwner(address _owner) public {
        require(msg.sender == creator);
        owner = _owner;      
    }

    function setCreator(address _creator) public {
        require(msg.sender == creator);
        creator = _creator;      
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public priceUpdateSubscribers;
    address[] public subscriberList;
    uint256 public pendingPrice;
    bool public priceUpdateInProgress;

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        
        // Set pending price and mark update as in progress
        pendingPrice = _price;
        priceUpdateInProgress = true;
        
        // Notify all subscribers before updating the actual price
        for (uint256 i = 0; i < subscriberList.length; i++) {
            address subscriber = subscriberList[i];
            if (priceUpdateSubscribers[subscriber]) {
                // External call to subscriber contract - vulnerability point
                (bool success, ) = subscriber.call(abi.encodeWithSignature("onPriceUpdate(uint256,uint256)", price, _price));
                // Continue even if call fails
            }
        }
        
        // Update actual price after all notifications
        price = _price;
        priceUpdateInProgress = false;
    }
    
    function subscribeToUpdates() public {
        if (!priceUpdateSubscribers[msg.sender]) {
            priceUpdateSubscribers[msg.sender] = true;
            subscriberList.push(msg.sender);
        }
    }
    
    function unsubscribeFromUpdates() public {
        priceUpdateSubscribers[msg.sender] = false;
        // Note: Not removing from subscriberList for simplicity
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
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