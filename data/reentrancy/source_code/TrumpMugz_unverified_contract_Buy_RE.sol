/*
 * ===== SmartInject Injection Details =====
 * Function      : Buy
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **State Update Reordering**: Moved critical state updates (Pot, ITM.owner, ITM.CPrice, ITM.reset, PotOwner) to occur AFTER the external call `sender_target.transfer(prev_val)` instead of before it.
 * 
 * 2. **Violation of Checks-Effects-Interactions Pattern**: The function now performs an external call before updating critical state variables, creating a reentrancy window.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls Buy() with sufficient ETH for item ID 0
 * - During the `sender_target.transfer(prev_val)` call, if sender_target is a malicious contract, it can re-enter
 * - At this point, the item's state (owner, price, reset status) has NOT been updated yet
 * - The attacker can observe the current state and prepare for the exploit
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls Buy() again for the same item ID during the reentrancy window
 * - Since ITM.owner hasn't been updated yet, the require check `require(msg.sender != ITM.owner)` still passes
 * - The price calculation uses the old ITM.CPrice value
 * - Attacker can purchase the item at the old price while the state is inconsistent
 * - Multiple state variables (Pot, ownership, prices) get updated twice or in unexpected ways
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The attacker can continue exploiting the inconsistent state across multiple transactions
 * - Each subsequent call during the reentrancy window operates on stale state
 * - The accumulated effect allows purchasing items at incorrect prices and manipulating the pot distribution
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The vulnerability relies on the persistent state between transactions where ownership, prices, and pot values are stored in contract storage.
 * 
 * 2. **Accumulated Effects**: Each reentrancy call operates on the previous transaction's state, creating cumulative effects that compound across multiple calls.
 * 
 * 3. **Complex State Dependencies**: The function has multiple interconnected state variables (item ownership, prices, pot accumulation, timer state) that require multiple transactions to fully exploit all inconsistencies.
 * 
 * 4. **External Call Timing**: The reentrancy window only exists during the external call, requiring multiple sequential calls to maximize exploitation of the inconsistent state.
 * 
 * This creates a realistic multi-transaction reentrancy vulnerability where the attacker must set up the exploit state in earlier transactions and then exploit the inconsistent state in subsequent transactions during the reentrancy window.
 */
pragma solidity ^0.4.21;

contract TrumpMugz {
    address owner;
    address helper = 0xd461f698B8bFaD15f7493264208e6884Bac73997;

    // New state variables
    address public topBuyer = address(0); // Initialize to zero address
    uint256 public topPurchase = 0;       // Initialize to zero

    uint256 public TimeFinish = 0;
    uint256 TimerResetTime = 7200;
    uint256 TimerStartTime = 360000;
    uint256 public Pot = 0;
    uint16 PIncr = 10000;
    uint16 DIVP = 10000;
    uint16 POTP = 0;
    uint16 WPOTPART = 9000;

    uint16 public DEVP = 500;
    uint16 public HVAL = 2500;
    uint256 BasicPrice = .03 ether;

    struct Item {
        address owner;
        uint256 CPrice;
        bool reset;
    }
    uint8 constant SIZE = 12;
    Item[SIZE] public ItemList;

    address public PotOwner;

    event ItemBought(address owner, uint256 newPrice, string says, uint8 id);
    event GameWon(address owner, uint256 paid, uint256 npot);

    modifier OnlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function changeOwnerAddress(address newOwner) public OnlyOwner {
        owner = newOwner;
    }

    function getHelper() public view returns (address) {
    return helper;
}

    function changeHelperAddress(address newHelper) public OnlyOwner {
        helper = newHelper;
    }

    function SetDevFee(uint16 tfee) public OnlyOwner {
        require(tfee <= 500);
        DEVP = tfee;
    }

    function SetHFee(uint16 hfee) public OnlyOwner {
        require(hfee <= 10000);
        require(hfee >= 1000);
        HVAL = hfee;
    }

    function TrumpMugz() public {
    address[12] memory originalOwners = [
        0x8bED01DccC86EB0120732e7b439095de051e6Ee3,
        0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
        0x48C04a000c6295B87ee42DdF736E6e96940B6aBC,
        0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
        0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
        0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
        0xc185B6C28c0AD4F38259e34E556d350E2630141D,
        0x77df690e021A023d34891A87f6179c7e2092cFD5,
        0xA920a36CCEb90d729f125b24B874DeE590e864B9,
        0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
        0x8c63Db24e8f4d65D04b0e6569b1BCF27B57F8972,
        0x6799103F589011dDAcDbA671145B9FA33E06E057
    ];



    for (uint8 i = 0; i < SIZE; i++) {
        ItemList[i] = Item(originalOwners[i], BasicPrice, true);
    }
    owner = msg.sender;
}

    function Buy(uint8 ID, string says) public payable {
        require(ID < SIZE);
        var ITM = ItemList[ID];
        if (TimeFinish == 0) {
            TimeFinish = block.timestamp;
        } else if (TimeFinish == 1) {
            TimeFinish = block.timestamp + TimerResetTime;
        }

        uint256 price = ITM.CPrice;

        if (ITM.reset) {
            price = BasicPrice;
        }

        if (msg.value >= price) {
            if (!ITM.reset) {
                require(msg.sender != ITM.owner);
            }
            if ((msg.value - price) > 0) {
                msg.sender.transfer(msg.value - price);
            }
            uint256 LEFT = DoDev(price);
            uint256 prev_val = 0;
            uint256 pot_val = LEFT;

            address sender_target = owner;

            if (!ITM.reset) {
                prev_val = (DIVP * LEFT) / 10000;
                pot_val = (POTP * LEFT) / 10000;
                sender_target = ITM.owner;
            } else {
                prev_val = LEFT;
                pot_val = 0;
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // VULNERABILITY: Critical state updates moved AFTER external call
            // This creates a window for reentrancy exploitation
            sender_target.transfer(prev_val);
            
            // State updates that should happen before external calls
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Pot = Pot + pot_val;
            ITM.owner = msg.sender;
            uint256 incr = PIncr;
            ITM.CPrice = (price * (10000 + incr)) / 10000;

            uint256 TimeLeft = TimeFinish - block.timestamp;

            if (TimeLeft < TimerStartTime) {
                TimeFinish = block.timestamp + TimerStartTime;
            }
            if (ITM.reset) {
                ITM.reset = false;
            }
            PotOwner = msg.sender;
            emit ItemBought(msg.sender, ITM.CPrice, says, ID);

            // Check and update top buyer and purchase
            if (price > topPurchase) {
                topPurchase = price;
                topBuyer = msg.sender;
                helper = topBuyer;
            }
        } else {
            revert();
        }
    }

    function DoDev(uint256 val) internal returns (uint256) {
        uint256 tval = (val * DEVP / 10000);
        uint256 hval = (tval * HVAL) / 10000;
        uint256 dval = tval - hval;

        owner.transfer(dval);
        helper.transfer(hval);
        return (val - tval);
    }
}