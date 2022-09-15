#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

struct item {
	unsigned long price;
	char * itemname;
	void (*print_ptr)();
};

void expire(int sig) {
	puts("Session expired.");
	exit(-1);
}

void win() {
	system("/bin/cat flag.txt");
	exit(0);
}

struct item * itemlist[10] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

int curID = 0;

void print_wheel() {
	puts("Itemtype: Wheel");
}

void print_oil() {
	puts("Itemtype: Oil");
}

void menu() {
	puts("===================");
	puts("1. Add an item.");
	puts("2. View an item.");
	puts("3. Remove an item.");
	puts("4. Assign a name to an item.");
	puts("5. Remove a name from an item.");
	puts("6. Submit the inventory.");
}

void add_item() {
	int index = 0;
	for(;index < 10; index++) {
		if(itemlist[index] == NULL) {
			break;
		}
		if(index == 9) {
			puts("You have reached the max amount of items in a single inventory submission!");
			return;
		}
	}
	struct item* newItem = (struct item*)malloc(sizeof(struct item));
	newItem->price = 0;
	newItem->itemname = NULL;
	itemlist[index] = newItem;
	printf("Item #%d created! Remember the item # for future reference.\n", index);
}

void view_item() {
	char input[8];
	puts("Select the item number to view:");
	printf("> ");
	fgets(input, 8, stdin);
	int select = atoi(input);
	if(select >= 0 && select < 10 && itemlist[select] != NULL) {
		printf("Price: %ld\n", itemlist[select]->price);
		if(itemlist[select]->itemname != NULL) {
			printf("Item name: %s\n", itemlist[select]->itemname);
			(*(itemlist[select]->print_ptr))();
		}

	}
	else {
		puts("Invalid item number.");
	}
}

void remove_item() {
        char input[8];
        puts("Select the item number to remove:");
        printf("> ");
        fgets(input, 8, stdin);
        int select = atoi(input);
        if(select >= 0 && select < 10 && itemlist[select] != NULL) {
		if(itemlist[select]->itemname != NULL) {
			free(itemlist[select]->itemname);
		}
		free(itemlist[select]);
		itemlist[select] = NULL;
	}
	else {
		puts("Invalid item number.");
	}
}

void assign_name() {
        char input[8];
        puts("Select the item number to assign a name to:");
        printf("> ");
        fgets(input, 8, stdin);
        int select = atoi(input);
        if(select >= 0 && select < 10 && itemlist[select] != NULL) {
                if(itemlist[select]->itemname != NULL) {
			puts("There is already a name assigned to this item!");
			return;
                }
		char * newname = (char *)malloc(0x18);
		puts("Enter the item name: ");
		fgets(newname, 0x18, stdin);
		itemlist[select]->itemname = newname;
		if(strstr(newname, "wheel") != NULL) {
			itemlist[select]->print_ptr = &print_wheel;
			itemlist[select]->price = 50;
		}
		else if(strstr(newname, "oil") != NULL) {
			itemlist[select]->print_ptr = &print_oil;
			itemlist[select]->price = 25;
		}
		else {
			puts("Unknown item type. Please enter the price manually");
			fgets(input, 8, stdin);
			itemlist[select]->price = atoi(input);
		}
        }
        else {
                puts("Invalid item number.");
        }
}

void remove_name() {
        char input[8];
        puts("Select the item number to remove a name from:");
        printf("> ");
        fgets(input, 8, stdin);
        int select = atoi(input);
        if(select >= 0 && select < 10 && itemlist[select] != NULL) {
                if(itemlist[select]->itemname == NULL) {
                        puts("No name is present!");
                        return;
                }
		free(itemlist[select]->itemname);
		itemlist[select]->itemname = NULL;
		itemlist[select]->price = 0;
		itemlist[select]->print_ptr = NULL;
	}
        else {
                puts("Invalid item number.");
        }
}

void submit() {
	puts("Your inventory is being submitted...");
	exit(0);
}

int main() {
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);
	signal(SIGALRM, &expire);
	alarm(180);
	puts("Welcome to the the C3 carshop inventory submission service.");
	puts("Employees: Here you can submit items to go onto the C3 carshop list!");
	while(1) {
		menu();
		char input[8];
		printf("> ");
		fgets(input, 8, stdin);
		int choice = atoi(input);
		switch(choice) {
			case 1:
				add_item();
				break;
			case 2:
				view_item();
				break;
			case 3:
				remove_item();
				break;
			case 4:
				assign_name();
				break;
			case 5:
				remove_name();
				break;
			case 6:
				submit();
				break;
			default:
				puts("Unknown option!");
				break;
		}
	}
}
