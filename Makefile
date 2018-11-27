# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: amaindro <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/05/31 14:50:34 by amaindro          #+#    #+#              #
#    Updated: 2018/05/31 15:05:26 by amaindro         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = Famine

SRC = main.c tools.c

OBJ = $(SRC:.c=.o)

LIB = -L libft/ -lft

MAKELIB = make -C ./libft

CLEANLIB = make clean -C ./libft

FCLEANLIB = make fclean -C ./libft

all : $(NAME)

test :
	cp /bin/ls test/
	gcc test/sample.c -o test/sample
	rm -rf /tmp/test
	cp -r test /tmp
	rm -rf /tmp/test2
	cp -r /tmp/test /tmp/test2
	
$(NAME) : $(OBJ) test
	$(MAKELIB)
	gcc -c $(SRC)
	gcc  -o $(NAME) $(OBJ) $(LIB)

clean :
	$(CLEANLIB)
	rm -rf $(OBJ)

fclean : clean
	$(FCLEANLIB)
	rm -rf $(NAME)

re : fclean all

.PHONY: all test clean fclean re

