/*
 * ===== SmartInject Injection Details =====
 * Function      : changeOwnerAddress
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-locked ownership transfer mechanism. The vulnerability requires multiple transactions: (1) initiate ownership change with timestamp storage, (2) complete ownership change after 24-hour delay. The vulnerability exploits block.timestamp manipulation where miners can adjust timestamps within the 900-second tolerance to either accelerate legitimate ownership changes or delay them indefinitely. This creates a multi-transaction attack vector where an attacker with mining power or MEV capabilities can manipulate the timing of ownership transfers, potentially preventing legitimate ownership changes or enabling unauthorized ones through timestamp manipulation across multiple blocks.
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public ownershipChangeTimestamp;
    address public pendingOwner;
    uint256 public constant OWNERSHIP_DELAY = 24 hours;
    
    function changeOwnerAddress(address newOwner) public OnlyOwner {
        if (pendingOwner == address(0)) {
            // First transaction: initiate ownership change
            pendingOwner = newOwner;
            ownershipChangeTimestamp[newOwner] = block.timestamp;
        } else if (pendingOwner == newOwner && block.timestamp >= ownershipChangeTimestamp[newOwner] + OWNERSHIP_DELAY) {
            // Second transaction: complete ownership change after delay
            owner = pendingOwner;
            pendingOwner = address(0);
            delete ownershipChangeTimestamp[newOwner];
        } else {
            // Reset if trying to change to different owner
            pendingOwner = newOwner;
            ownershipChangeTimestamp[newOwner] = block.timestamp;
        }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

            Pot = Pot + pot_val;
            sender_target.transfer(prev_val);
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